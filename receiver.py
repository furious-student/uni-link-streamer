import os
import select
import sys
import time
from typing import Dict

from node_type import *

# Constants
TIMEOUT_INTERVAL_RECEIVER = 15  # Timeout interval for keep-alive mechanism in seconds


class Receiver(NodeType, ABC):
    __curr_message_status: Dict[int, Tuple[bytes, bool]]
    __curr_message_isfile: bool
    __curr_message_f_name_size: int
    __curr_message_has_last: bool
    __last_keep_alive_time: time
    __curr_message_info_printed: bool

    def __init__(self, src_ip: str, src_port: int,
                 curr_message_received_packets: list[int] = None,
                 curr_message_sent_packets: list[int] = None,
                 connection_open: bool = False
                 ):
        super().__init__(dst_ip="", dst_port=-1, src_ip=src_ip, src_port=src_port,
                         curr_message_received_packets=curr_message_received_packets,
                         curr_message_sent_packets=curr_message_sent_packets,
                         connection_open=connection_open)
        self.__curr_message_f_name_size = 0
        self.__curr_message_info_printed = False
        self.__curr_message_isfile = False
        self.__curr_message_has_last = False
        self.__last_keep_alive_time = None

    def set_dst_address(self, dst_ip, dst_port):
        super().set_dst_address(dst_ip=dst_ip, dst_port=dst_port)

    def start(self, soft: bool = False, node_socket: socket.socket = None) -> \
            Union[None, Tuple[str, socket.socket, Tuple[str, int], Tuple[str, int], List[int], List[int]]]:
        if node_socket is None:
            # Create a UDP socket
            super().set_socket(socket.socket(socket.AF_INET,  # Internet
                                             socket.SOCK_DGRAM))  # UDP
            self.get_socket().bind(self.get_src_address())
        else:
            self.set_socket(node_socket=node_socket)

        if soft is True:
            print(">> Switched to Receiver")
        else:
            print(">> Receiver is up")
        print(f"   Receiver listens on {self.get_src_address()}")
        print(f"   To display all available commands, type 'help!'\n"
              f">> ", end="")

        # Start the listening thread
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

        message_check_thread = threading.Thread(target=self.check_message_status)
        message_check_thread.start()

        while not self.is_shutdown_event_set():
            self.listen_input()
            if self.get_switch_state() is not None and self.is_switch_sent():
                self.shutdown()

        # wait until threads finish
        listen_thread.join()
        message_check_thread.join()
        if self.get_switch_state() is None:
            self.get_socket().close()
        return self.get_switch_state()

    def listen_input(self) -> None:
        rlist, _, _ = select.select([sys.stdin], [], [], 5)
        if not rlist:
            return

        input_message = sys.stdin.readline().strip()
        if self.is_shutdown_event_set() is True:
            print(">> Program ended")
            return
        if len(input_message) <= 0:
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
            print(f">> Command '{command[1]}' is not a valid command\n"
                  f">> ", end="")

    def handle_cmd(self, cmd: str, arg: str) -> None:
        if cmd == "switch!":
            if not self.is_connection_open():
                print(">> Connection is not open\n>> ", end="")
                return
            self.send_packet(create_packet(flag=6, seq_num=0, payload=b''))
            self.inc_curr_message_sent_packets(index=6)
            self.set_switch_sent(True)
        elif cmd == "end!":
            if not self.is_connection_open():
                print(">> Connection is not open\n>> ", end="")
                return
            self.set_fin_sent(True)
            self.send_packet(create_packet(flag=8, seq_num=0, payload=b''))
            self.inc_curr_message_sent_packets(index=8)
        elif cmd == "info!":
            print(f">> INFO\n"
                  f"   ---\n"
                  f"   node_type:       {self.__class__}\n"
                  f"   dst_address:     {self.get_dst_address()}\n"
                  f"   src_address:     {self.get_src_address()}\n"
                  f"   connection_open: {self.is_connection_open()}\n"
                  f"   ---\n"
                  f">> ", end="")
        elif cmd == "help!":
            print(f">> HELP\n"
                  f"   ---\n"
                  f"   'end!':     Sends a signal to the other node that you want to\n"
                  f"               close the connection. If a FIN is received from\n"
                  f"               the other node, the connection is closed and the\n"
                  f"               program terminates.\n"
                  f"   'help!':    Displays this.\n"
                  f"   'info!':    Displays info about this node.\n"
                  f"   'switch!':  Sends a signal to the other node that you want\n"
                  f"               to switch roles.\n"
                  f"   ---\n"
                  f">> ", end="")
        else:
            print(f">> Command '{cmd}' is not a valid command\n"
                  f">> ", end="")

    def write_file(self, location: str, file_name: str, content: bytes) -> str:
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
        return os.path.abspath(path)

    def listen(self):
        start_keepalive = True
        self.__curr_message_info_printed = False
        while not self.is_shutdown_event_set():
            try:
                # Set a timeout for the recvfrom operation
                self.get_socket().settimeout(2)
                flag, seq_num, crc_check, data, src_addr = self.receive_packet()
                # Reset the timeout to None after a successful reception
                self.get_socket().settimeout(None)
                if flag != 5:
                    if flag == 1 or flag == 2 or flag == 10:
                        print("   ", end="")
                    print_packet(flag, seq_num, crc_check)
            except socket.timeout:
                self.get_socket().settimeout(None)
                continue
            if self.is_connection_open() is True and crc_check is False:
                self.send_packet(create_packet(flag=4, seq_num=seq_num, payload=b''))  # send n_ack if CRC's differ
                self.inc_curr_message_received_packets(index=12)
                self.inc_curr_message_sent_packets(index=4)
                continue
            if flag == 0:
                # syn
                self.inc_curr_message_received_packets(index=0)
                self.set_dst_address(dst_ip=src_addr[0], dst_port=src_addr[1])
                self.set_connection_open(True)
                self.send_packet(create_packet(flag=0, seq_num=0, payload=b''))
                self.inc_curr_message_sent_packets(index=0)
            elif flag == 1:
                # f_data
                self.update_message_status(seq_num=seq_num, data=data)
                self.send_packet(create_packet(flag=3, seq_num=seq_num, payload=b''))
                self.inc_curr_message_received_packets(index=1)
                self.inc_curr_message_sent_packets(index=3)
                self.__curr_message_isfile = True
                self.__curr_message_f_name_size += 1
            elif flag == 2:
                # data
                self.update_message_status(seq_num=seq_num, data=data)
                self.send_packet(create_packet(flag=3, seq_num=seq_num, payload=b''))
                self.inc_curr_message_received_packets(index=2)
                self.inc_curr_message_sent_packets(index=3)
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
                self.inc_curr_message_received_packets(index=5)
                self.handle_keep_alive(seq_num=seq_num)
            elif flag == 6:
                # switch
                self.inc_curr_message_received_packets(index=6)
                if self.is_switch_sent() is False:
                    self.send_packet(create_packet(flag=6, seq_num=seq_num, payload=b''))
                    self.inc_curr_message_sent_packets(index=6)
                    self.set_switch_sent(True)
                state = ("sender",
                         self.get_socket(),
                         self.get_dst_address(),
                         self.get_src_address(),
                         self.get_curr_message_received_packets(),
                         self.get_curr_message_sent_packets())
                self.set_switch_state(state)
            elif flag == 7:
                pass  # n_switch
            elif flag == 8:
                # fin
                self.set_connection_open(False)
                self.inc_curr_message_received_packets(index=8)
                if not self.is_fin_sent():
                    self.send_packet(create_packet(flag=8, seq_num=seq_num, payload=b''))
                    self.inc_curr_message_sent_packets(index=8)
                self.shutdown()
            elif flag == 9:
                pass  # n_fin
            elif flag == 10:
                # last
                self.update_message_status(seq_num=seq_num, data=data)
                self.send_packet(create_packet(flag=3, seq_num=seq_num, payload=b''))
                self.inc_curr_message_received_packets(index=10)
                self.inc_curr_message_sent_packets(index=3)
                self.__curr_message_has_last = True
            elif flag == 11:
                # init/zero packet
                packets_len = int.from_bytes(data, byteorder='big', signed=False)
                self.init_message_status(packets_len)
                self.send_packet(create_packet(flag=3, seq_num=seq_num, payload=b''))
                self.inc_curr_message_received_packets(index=11)
                self.inc_curr_message_sent_packets(index=3)

    def check_message_status(self) -> None:
        while not self.is_shutdown_event_set():
            # Check if all packets have been received
            if self.__curr_message_has_last and not self.has_missing_packet() and not self.__curr_message_info_printed:
                self.__curr_message_info_printed = True
                self.handle_message()

    def handle_keep_alive(self, seq_num):
        # Respond with a keep-alive message
        self.send_packet(create_packet(flag=5, seq_num=seq_num, payload=b''))
        self.inc_curr_message_sent_packets(index=5)
        self.__last_keep_alive_time = time.time()

    def check_timeout(self):
        while not self.is_shutdown_event_set():
            # Check for keep-alive timeout
            current_time = time.time()
            if self.__last_keep_alive_time is not None and \
                    current_time - self.__last_keep_alive_time > TIMEOUT_INTERVAL_RECEIVER:
                print("Keep-alive timeout\n"
                      ">> ", end="")
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

    def rebuild_data(self, is_file: bool = False, f_name_size: int = 0) -> bytes:
        whole_data = b''
        for seq_num, data_tuple in self.__curr_message_status.items():
            if is_file is True and f_name_size > 0:
                f_name_size -= 1
                continue
            data, _ = data_tuple
            whole_data += data
        return whole_data

    def handle_message(self) -> None:
        self.print_received_packet_stats()
        self.print_sent_packet_stats()
        self.init_curr_message_received_packets()
        self.init_curr_message_sent_packets()
        if self.__curr_message_isfile:
            file_name = ""
            for i in range(1, 1 + self.__curr_message_f_name_size):
                file_name += self.__curr_message_status[i][0].decode(encoding='utf-8')
            file_name = file_name
            location = "./received_files/"
            abs_path = self.write_file(location=location,
                                       file_name=file_name,
                                       content=self.rebuild_data(is_file=True,
                                                                 f_name_size=self.__curr_message_f_name_size))
            print(f">> Received a file '{file_name}'\n"
                  f"   Stored path: {abs_path}\n"
                  f">> ", end="")
        else:
            text = self.rebuild_data().decode(encoding='utf-8')
            print(f">> Received message '{text}'\n"
                  f">> ", end="")
        self.__curr_message_f_name_size = 0
        self.__curr_message_info_printed = False
        self.__curr_message_has_last = False
        self.__curr_message_isfile = False

    def has_missing_packet(self) -> bool:
        for seq_num, data_tuple in self.__curr_message_status.items():
            _, received = data_tuple
            if received is False:
                return True
        return False
