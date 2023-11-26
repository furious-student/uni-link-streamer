import os
import socket
from abc import ABC
import time
from typing import Tuple, Dict

from node_type import *


# Constants
TIMEOUT_INTERVAL_RECEIVER = 15  # Timeout interval for keep-alive mechanism in seconds


class Receiver(NodeType, ABC):
    __curr_message_status: Dict[int, Tuple[bytes, bool]]
    __curr_message_nack: int
    __curr_message_isfile: bool
    __curr_message_has_last: bool
    __last_keep_alive_time: time

    def __init__(self, src_ip: str, src_port: int):
        super().__init__("", -1, src_ip=src_ip, src_port=src_port)
        self.__curr_message_nack = 0
        self.__curr_message_isfile = False
        self.__curr_message_has_last = False
        self.__last_keep_alive_time = None

    def set_dst_address(self, dst_ip, dst_port):
        super().set_dst_address(dst_ip=dst_ip, dst_port=dst_port)

    def start(self) -> None:
        # Create a UDP socket
        super().set_socket(socket.socket(socket.AF_INET,  # Internet
                                         socket.SOCK_DGRAM))  # UDP
        self.get_socket().bind(self.get_src_address())
        print(">> Receiver is up")
        print(f">> Receiver listens on {self.get_src_address()}")
        print(">> To display all available commands, type 'help!'")
        self.listen()

    def listen_input(self) -> str:
        message = input()
        return message

    def handle_cmd(self, cmd: str, arg: str) -> None:
        pass

    def keep_alive(self) -> None:
        pass

    def write_file(self, location: str, file_name: str, content: bytes) -> None:
        # If the file already exists, find a new name
        path = location + file_name
        if os.path.isfile(path):
            base_name, extension = os.path.splitext(path)
            counter = 1
            new_file_name = f"{base_name}_{counter}{extension}"
            while os.path.isfile(new_file_name):
                counter += 1
                new_file_name = f"{base_name}_{counter}{extension}"
            path = new_file_name
        # Create the file
        file = open(path, 'wb')
        file.write(content)
        file.close()

    def listen(self):
        start_keepalive = True
        curr_message_info_printed = False
        while not self.is_shutdown_event_set():
            try:
                # Set a timeout for the recvfrom operation
                self.get_socket().settimeout(1.0)
                flag, seq_num, crc_check, data, src_addr = self.receive_packet()
                if flag != 5:
                    print(f">> flag: {flag} | seq_num: {seq_num} | crc_check: {crc_check}")
                # Reset the timeout to None after a successful reception
                self.get_socket().settimeout(None)
            except socket.timeout:
                continue
            if self.is_connection_open() is True and crc_check is False:
                self.send_packet(create_packet(flag=4, seq_num=seq_num, payload=b''))  # send n_ack if CRC's differ
                self.__curr_message_nack += 1
                continue
            if flag == 0:
                # syn
                self.set_dst_address(dst_ip=src_addr[0], dst_port=src_addr[1])
                self.set_connection_open(True)
                self.send_packet(create_packet(flag=0, seq_num=0, payload=b''))
            elif flag == 1:
                # f_data
                self.update_message_status(seq_num=seq_num, data=data)
                self.send_packet(create_packet(flag=3, seq_num=seq_num, payload=b''))
                self.__curr_message_isfile = True
            elif flag == 2:
                # data
                self.update_message_status(seq_num=seq_num, data=data)
                self.send_packet(create_packet(flag=3, seq_num=seq_num, payload=b''))
            elif flag == 3:
                pass  # ack
            elif flag == 4:
                pass  # n_ack
            elif flag == 5:
                # keep_alive
                if start_keepalive is True:
                    # Start a thread for keep-alive timeout checks
                    timeout_thread = threading.Thread(target=self.check_timeout)
                    timeout_thread.start()
                    start_keepalive = False  # to only start the thread after first keepalive arrives
                self.handle_keep_alive(seq_num=seq_num)
            elif flag == 6:
                pass  # switch
            elif flag == 7:
                pass  # n_switch
            elif flag == 8:
                pass  # fin
            elif flag == 9:
                pass  # n_fin
            elif flag == 10:
                # last
                self.update_message_status(seq_num=seq_num, data=data)
                self.send_packet(create_packet(flag=3, seq_num=seq_num, payload=b''))
                self.__curr_message_has_last = True
            elif flag == 11:
                # init/zero packet
                packets_len = int.from_bytes(data, byteorder='big', signed=False)
                self.init_message_status(packets_len)
                curr_message_info_printed = False
                self.__curr_message_has_last = False
                self.__curr_message_isfile = False
                self.send_packet(create_packet(flag=3, seq_num=seq_num, payload=b''))

            # Check if all packets have been received
            if self.__curr_message_has_last and not self.has_missing_packet() and not curr_message_info_printed:
                curr_message_info_printed = True
                self.handle_message()

    def handle_keep_alive(self, seq_num):
        # Respond with a keep-alive message
        self.send_packet(create_packet(flag=5, seq_num=seq_num, payload=b''))
        self.__last_keep_alive_time = time.time()

    def check_timeout(self):
        while not self.is_shutdown_event_set():
            # Check for keep-alive timeout
            current_time = time.time()
            if self.__last_keep_alive_time is not None and\
                    current_time - self.__last_keep_alive_time > TIMEOUT_INTERVAL_RECEIVER:
                print(">> Keep-alive timeout\n>> Shutting down the connection.")
                self.shutdown()
                return

            # Sleep for a short interval before checking again
            time.sleep(1)

    def init_message_status(self, packets_len) -> None:
        self.__curr_message_status = dict()
        for i in range(1, packets_len):
            self.__curr_message_status.update({i: (b'', False)})

    def update_message_status(self, seq_num, data: bytes):
        # Check if the key is in the dictionary
        if seq_num in self.__curr_message_status:
            # Update the bool value
            self.__curr_message_status[seq_num] = (data, True)

    def rebuild_data(self, is_file: bool = False) -> bytes:
        whole_data = b''
        for seq_num, data_tuple in self.__curr_message_status.items():
            if is_file is True and seq_num == 1:
                continue
            data, _ = data_tuple
            whole_data += data
        return whole_data

    def handle_message(self) -> None:
        print(f">> Received 1 INIT packet and {len(self.__curr_message_status)} DATA packets\n"
              f">> Received {self.__curr_message_nack} corrupted packets")
        self.__curr_message_nack = 0
        if self.__curr_message_isfile:
            file_name = self.__curr_message_status[1][0].decode(encoding='utf-8')
            location = input(f">> Received a file '{file_name}'."
                             f" Where to store it? ")
            self.write_file(location=location, file_name=file_name, content=self.rebuild_data(is_file=True))
        else:
            text = self.rebuild_data().decode(encoding='utf-8')
            print(f">> {text}")

    def has_missing_packet(self) -> bool:
        for seq_num, data_tuple in self.__curr_message_status.items():
            _, received = data_tuple
            if received is False:
                return True
        return False
