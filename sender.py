import threading
from abc import ABC
import time
from typing import Dict

from node_type import *


# Constants
TIMEOUT_INTERVAL_SENDER = 5  # Timeout interval for keep-alive mechanism in seconds
MAX_RETRIES = 3  # Maximum number of retries for keep-alive mechanism


def message_to_bytes(message: str) -> bytes:
    return message.encode(encoding="utf-8")


def file_input(file_name: str) -> bytes:
    file = open(file_name, mode='rb')  # b means binary
    file_data = file.read()
    return file_data


class Sender(NodeType, ABC):
    __curr_message_status: Dict[int, Tuple[bytes, bool]]
    __curr_message_nack: int
    __frag_size: int
    __keep_alive_timer: threading
    __keep_alive_retries: int
    __response_received_event: threading.Event

    def __init__(self, dst_ip: str, dst_port: int):
        super().__init__(dst_ip=dst_ip, dst_port=dst_port, src_ip="127.0.0.1", src_port=1234)
        self.__frag_size = 10
        self.__curr_message_nack = 0
        self.__keep_alive_timer = None
        self.__keep_alive_retries = 0
        self.__response_received_event = threading.Event()

    def start(self) -> None:
        # Create a UDP socket
        super().set_socket(socket.socket(socket.AF_INET,      # Internet
                                         socket.SOCK_DGRAM))  # UDP
        self.get_socket().bind(self.get_src_address())
        print(">> Sender is up")
        print(f">> Messages will be send over to {self.get_dst_address()}")
        print(">> To display all available commands, type 'help!'")

        # Start the listening thread
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

        while not self.is_shutdown_event_set():
            self.listen_input()

    def fragment_data(self, data: bytes) -> List[bytes]:
        # Calculate the number of fragments needed
        frag_num = len(data) // self.__frag_size + (len(data) % self.__frag_size != 0)
        fragments = [data[i*self.__frag_size:(i+1)*self.__frag_size] for i in range(frag_num)]
        return fragments

    def map_packets(self, packets: List[bytes]) -> None:
        self.__curr_message_status = dict()
        for seq_num, frag in enumerate(packets):
            self.__curr_message_status.update({seq_num: (frag, False)})

    def create_data_packets(self, data: bytes, init_seq_num: int) -> List[bytes]:
        flag = 2  # flag 2 = DATA
        data_fragments = self.fragment_data(data=data)
        packets = list()
        for index, frag in enumerate(data_fragments):
            if index == len(data_fragments)-1:
                flag = 10
            packet = create_packet(flag=flag, seq_num=init_seq_num, payload=frag)
            packets.append(packet)
            init_seq_num += 1
        return packets

    def send_all_packets(self, packets: List[bytes]) -> None:
        self.map_packets(packets=packets)
        # send first (must be acked)
        while self.__curr_message_status[0][1] is False:
            self.send_packet(packet=packets[0])
            # Wait for the response
            if self.__response_received_event.wait(timeout=2):
                # Clear the event for the next iteration
                self.__response_received_event.clear()
        # send rest
        number = 0
        for pkt in packets:
            # skip the init packet as it has already been sent
            if number == 0:
                number += 1
                continue
            # Inject error in every third packet
            if number % 3 == 2:
                pkt += b'\xf1'
            self.send_packet(pkt)
            number += 1
        # keep sending unacked packets until all are acked
        while self.has_missing_packet():
            self.resend_unacked()
        print(f">> Sent {len(self.__curr_message_status)} packets\n"
              f">> Received {self.__curr_message_nack} N_ACK packets")
        self.__curr_message_nack = 0

    def resend_unacked(self) -> None:
        # Waiting time before starting to resend
        time.sleep(2)
        # Send the unacked packets
        for seq_num, data_tuple in self.__curr_message_status.items():
            packet, received = data_tuple
            if received is False:
                self.send_packet(packet=packet)

    def send_file_data(self, path) -> None:
        b_file = file_input(file_name=path)
        b_file_name = message_to_bytes(path)
        first_packet = create_packet(flag=1, seq_num=1, payload=b_file_name)
        packets = [first_packet] + self.create_data_packets(data=b_file, init_seq_num=2)
        zero_packet = create_packet(11, 0, (len(packets)+1).to_bytes(4, byteorder="big", signed=False))
        packets = [zero_packet] + packets
        self.send_all_packets(packets=packets)

    def listen_input(self) -> None:
        input_message = text_input()
        if self.is_shutdown_event_set() is True:
            print(">> Program ended")
            return
        command = is_command(input_message)
        if command[0]:
            cmd = command[1]
            if command[2] is None:
                args = None
            else:
                args = command[2][0]
            self.handle_cmd(cmd=cmd, arg=args)
        else:
            if not self.is_connection_open():
                print(">> Connection is not open")
                return
            b_message = message_to_bytes(input_message)
            data_packets = self.create_data_packets(data=b_message, init_seq_num=1)
            zero_packet = create_packet(11, 0, (len(data_packets) + 1).to_bytes(4, byteorder="big", signed=False))
            data_packets = [zero_packet] + data_packets
            self.send_all_packets(data_packets)

    def handle_cmd(self, cmd: str, arg: str) -> None:
        if cmd == "file!":
            if not self.is_connection_open():
                print(">> Connection is not open")
                return
            self.send_file_data(path=arg)
        elif cmd == "switch!":
            if not self.is_connection_open():
                print(">> Connection is not open")
                return
            pass
        elif cmd == "end!":
            if not self.is_connection_open():
                print(">> Connection is not open")
                return
            pass
        elif cmd == "f_size!":
            self.__frag_size = int(arg)
        elif cmd == "syn!":
            self.send_packet(create_packet(flag=0, seq_num=0, payload=b''))
        elif cmd == "info!":
            print(f">> INFO\n"
                  f"   ---\n"
                  f"   node_type:       {self.__class__}\n"
                  f"   fragment_size:   {self.__frag_size}\n"
                  f"   dst_address:     {self.get_dst_address()}\n"
                  f"   src_address:     {self.get_src_address()}\n"
                  f"   connection_open: {self.is_connection_open()}\n"
                  f"   ---")

    def listen(self):
        while not self.is_shutdown_event_set():
            try:
                # Set a timeout for the recvfrom operation
                self.get_socket().settimeout(1.0)  # 1.0 second timeout
                flag, seq_num, crc_check, data, src_addr = self.receive_packet()
                # Reset the timeout to None after a successful reception
                self.get_socket().settimeout(None)
            except socket.timeout:
                continue
            if crc_check is False:
                continue
            if flag == 0:
                # syn
                self.set_connection_open(True)
                # Start the keep-alive mechanism
                self.start_keep_alive()
            elif flag == 1:
                pass  # f_data
            elif flag == 2:
                pass  # data
            elif flag == 3:
                # ack
                if seq_num == 0:
                    self.__response_received_event.set()
                self.update_message_status(seq_num=seq_num)
            elif flag == 4:
                # n_ack
                self.__curr_message_nack += 1
            elif flag == 5:
                # keep_alive
                # Reset the keep-alive timer
                self.reset_keep_alive_timer()
            elif flag == 6:
                pass  # switch
            elif flag == 7:
                pass  # n_switch
            elif flag == 8:
                pass  # fin
            elif flag == 9:
                pass  # n_fin
            elif flag == 10:
                pass  # last
            elif flag == 11:
                pass  # init/zero packet

    def start_keep_alive(self) -> None:
        self.__keep_alive_timer = threading.Timer(TIMEOUT_INTERVAL_SENDER, self.keep_alive_timeout)
        self.__keep_alive_timer.start()

    def keep_alive_timeout(self) -> None:
        if self.__keep_alive_retries < MAX_RETRIES:
            # print("Sending keep-alive message.\n>> ", end="")
            # Send keep-alive message
            self.send_packet(create_packet(flag=5, seq_num=0, payload=b''))
            self.__keep_alive_retries += 1
            # Restart the keep-alive timer
            self.start_keep_alive()
        else:
            print("Keep-alive timeout\n>> Shutting down the connection\n>> ", end="")
            self.shutdown()

    def reset_keep_alive_timer(self) -> None:
        # Reset the keep-alive timer after receiving an acknowledgment
        if self.__keep_alive_timer is not None:
            self.__keep_alive_timer.cancel()
            self.__keep_alive_retries = 0
            self.start_keep_alive()

    def has_missing_packet(self) -> bool:
        for seq_num, data_tuple in self.__curr_message_status.items():
            _, received = data_tuple
            if received is False:
                return True
        return False

    def update_message_status(self, seq_num):
        # Check if the key is in the dictionary
        if seq_num in self.__curr_message_status:
            # Destructure the tuple
            data, acked = self.__curr_message_status[seq_num]
            # Update the bool value
            self.__curr_message_status[seq_num] = (data, True)

