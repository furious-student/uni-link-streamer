import os.path
import select
import socket
import sys
import time
from typing import Dict

from node_type import *

# Constants
TIMEOUT_INTERVAL_SENDER = 5  # Timeout interval for keep-alive mechanism in seconds
MAX_RETRIES = 3  # Maximum number of retries for keep-alive mechanism
MAX_SEQ_NUM = 268_435_455


def message_to_bytes(message: str) -> bytes:
    return message.encode(encoding="utf-8")


def file_input(file_name: str) -> bytes:
    file = open(file_name, mode='rb')  # b means binary
    file_data = file.read()
    return file_data


class Sender(NodeType, ABC):
    __curr_message_status: Dict[int, Tuple[bytes, bool]]
    __frag_size: int
    __keep_alive_timer: threading
    __keep_alive_retries: int
    __response_received_event: threading.Event

    def __init__(self, dst_ip: str, dst_port: int,
                 src_ip="169.254.56.16", src_port=2000,
                 curr_message_received_packets: list[int] = None,
                 curr_message_sent_packets: list[int] = None,
                 connection_open: bool = False
                 ):
        super().__init__(dst_ip=dst_ip, dst_port=dst_port, src_ip=src_ip, src_port=src_port,
                         curr_message_received_packets=curr_message_received_packets,
                         curr_message_sent_packets=curr_message_sent_packets,
                         connection_open=connection_open)
        self.__frag_size = 1466
        self.__keep_alive_timer = None
        self.__keep_alive_retries = 0
        self.__response_received_event = threading.Event()

    def set_src_address(self, src_ip, src_port):
        super().set_src_address(src_ip=src_ip, src_port=src_port)

    def start(self, soft: bool = False, node_socket: socket.socket = None) -> \
            Union[None, Tuple[str, socket.socket, Tuple[str, int], Tuple[str, int], List[int], List[int]]]:
        if node_socket is None:
            # Create a UDP socket
            super().set_socket(socket.socket(socket.AF_INET,  # Internet
                                             socket.SOCK_DGRAM))  # UDP
            self.get_socket().bind(self.get_src_address())
        else:
            self.set_socket(node_socket=node_socket)
            # Start the keep-alive mechanism
            self.start_keep_alive()

        if soft is True:
            print("   Switched to Sender")
        else:
            print(">> Sender is up")
        print(f"   Messages will be send over to {self.get_dst_address()}")
        print(f"   To display all available commands, type 'help!'")

        # Start the listening thread
        listen_thread = threading.Thread(target=self.listen)
        listen_thread.start()

        print(">> ", end="")
        while not self.is_shutdown_event_set():
            self.listen_input()
            if self.get_switch_state() is not None and self.is_switch_sent():
                self.shutdown(soft=True)

        # wait until thread finish
        listen_thread.join()
        if self.get_switch_state() is None:
            self.get_socket().close()
        return self.get_switch_state()

    def fragment_data(self, data: bytes) -> List[bytes]:
        # Calculate the number of fragments needed
        frag_num = len(data) // self.__frag_size + (len(data) % self.__frag_size != 0)
        fragments = [data[i * self.__frag_size:(i + 1) * self.__frag_size] for i in range(frag_num)]
        return fragments

    def map_packets(self, packets: List[bytes]) -> None:
        self.__curr_message_status = dict()
        for seq_num, frag in enumerate(packets):
            self.__curr_message_status.update({seq_num: (frag, False)})

    def create_packets(self, flag: int, data: bytes, init_seq_num: int) -> List[bytes]:
        # flag 2 = DATA
        data_fragments = self.fragment_data(data=data)
        packets = list()
        for index, frag in enumerate(data_fragments):
            if index == len(data_fragments) - 1 and flag != 1:
                flag = 10
            packet = create_packet(flag=flag, seq_num=init_seq_num, payload=frag)
            packets.append(packet)
            init_seq_num += 1
        return packets

    def send_all_packets(self, packets: List[bytes]) -> None:
        if len(packets) > 268_435_455:
            print(">> Cannon send message because of too many packets. Try increasing the fragment size or sending "
                  "smaller file.")
            return
        self.map_packets(packets=packets)
        self.init_curr_message_received_packets()
        self.init_curr_message_sent_packets()
        # send INIT packet (must be acked)
        while self.__curr_message_status[0][1] is False and not self.is_shutdown_event_set():
            self.send_packet(packet=packets[0])
            self.inc_curr_message_sent_packets(index=11)
            # Wait for the response
            if self.__response_received_event.wait(timeout=2):
                # Clear the event for the next iteration
                self.__response_received_event.clear()
        # send rest
        number = 0
        for pkt in packets:
            if self.is_shutdown_event_set():
                break
            # skip the init packet as it has already been sent
            if number == 0:
                number += 1
                continue
            # Inject error in every third packet
            # if number % 3 == 2:
            #     pkt += b'\xf1'
            self.send_packet(pkt)
            self.inc_curr_message_sent_packets(index=2)
            number += 1
            if number % 500 == 0:
                time.sleep(2)
        # keep sending unacked packets until all are acked
        while self.has_missing_packet() and not self.is_shutdown_event_set():
            self.resend_unacked()
        self.print_received_packet_stats()
        self.print_sent_packet_stats()
        print(">> ", end="")

    def resend_unacked(self) -> None:
        # Waiting time before starting to resend
        time.sleep(2)
        # Send the unacked packets
        for seq_num, data_tuple in self.__curr_message_status.items():
            packet, received = data_tuple
            if received is False:
                self.send_packet(packet=packet)
                self.inc_curr_message_sent_packets(index=2)

    def send_file_data(self, path) -> None:
        b_file = file_input(file_name=path)
        file_name_packets = self.create_packets(flag=1, init_seq_num=1,
                                                data=message_to_bytes(os.path.basename(path)))
        packets = file_name_packets + self.create_packets(flag=2, data=b_file, init_seq_num=len(file_name_packets) + 1)
        zero_packet = create_packet(flag=11, seq_num=0,
                                    payload=(len(packets) + 1).to_bytes(4, byteorder="big", signed=False))
        packets = [zero_packet] + packets
        self.send_all_packets(packets=packets)

    def send_text(self, input_message: str, corrupt: bool = False) -> None:
        b_message = message_to_bytes(input_message)
        data_packets = self.create_packets(flag=2, data=b_message, init_seq_num=1)
        zero_packet = create_packet(11, 0, (len(data_packets) + 1).to_bytes(4, byteorder="big", signed=False))
        data_packets = [zero_packet] + data_packets
        self.send_all_packets(data_packets)

    def listen_input(self) -> None:
        rlist, _, _ = select.select([sys.stdin], [], [], 1)
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
            arg = command[2]
            self.handle_cmd(cmd=cmd, arg=arg)
        else:
            if not self.is_connection_open():
                print(">> Connection is not open\n>> ", end="")
                return
            self.send_text(input_message=input_message)

    def handle_cmd(self, cmd: str, arg: str) -> None:
        if cmd == "file!":
            if not self.is_connection_open():
                print(">> Connection is not open\n>> ", end="")
                return
            self.send_file_data(path=arg)
        elif cmd == "switch!":
            if not self.is_connection_open():
                print(">> Connection is not open\n>> ", end="")
                return
            self.send_packet(create_packet(flag=6, seq_num=0, payload=b''))
            self.inc_curr_message_sent_packets(index=6)
            self.set_switch_sent(True)
            print(">> ", end="")
        elif cmd == "end!":
            if not self.is_connection_open():
                print(">> Connection is not open\n>> ", end="")
                return
            self.set_fin_sent(True)
            self.send_packet(create_packet(flag=8, seq_num=0, payload=b''))
            self.inc_curr_message_sent_packets(index=8)
        elif cmd == "fsize!":
            self.__frag_size = int(arg)
            print(">> ", end="")
        elif cmd == "syn!":
            if self.is_connection_open():
                print(">> Connection is already opened\n>> ", end="")
                return
            self.send_packet(create_packet(flag=0, seq_num=0, payload=b''))
            self.inc_curr_message_sent_packets(index=0)
            print(">> ", end="")
        elif cmd == "m!":
            if arg is None:
                print(f">> No argument specified for command {cmd}\n>> ", end="")
                return
            self.send_text(input_message=arg)
        elif cmd == "m!":
            if arg is None:
                print(f">> No argument specified for command '{cmd}'\n>> ", end="")
                return
            self.send_text(input_message=arg, corrupt=True)
        elif cmd == "info!":
            print(f">> INFO\n"
                  f"   ---\n"
                  f"   node_type:       {self.__class__}\n"
                  f"   fragment_size:   {self.__frag_size}\n"
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
                  f"   'file!':    Must have a second argument (a file name) separa-\n"
                  f"               ted with space, e.g. 'file! example.txt'. This \n"
                  f"               command sends a file to the other node.\n"
                  f"   'fsize!':   With this command you can set the fragment size\n"
                  f"               in bytes of each packet sent. The fragment size\n"
                  f"               is an integer taken as a second argument, e.g. \n"
                  f"               'fsize! 500' sets the fragment size to 500 bytes.\n"
                  f"               The argument must be from interval <1, 1466>.\n"
                  f"               Defaults to 1466.\n"
                  f"   'help!':    Displays this.\n"
                  f"   'info!':    Displays info about this node.\n"
                  f"   'm!':       Same as plain text (see bellow). All following\n"
                  f"               words are interpreted as a textual message to be\n"
                  f"               sent over to the other node. If no words follow,\n"
                  f"               nothing happens.\n"
                  f"   'merr!':    Same as 'm!' but deliberately corrupts a random\n"
                  f"               DATA packet (by modifying its check sum) to test\n"
                  f"               the functionality of the ARQ mechanism.\n"
                  f"   'switch!':  Sends a signal to the other node that you want\n"
                  f"               to switch roles.\n"
                  f"   'syn!':     Sends a signal to the other node that you want to\n"
                  f"               initiate connection. If a SYN is received from\n"
                  f"               the other node, the connection is opened and you\n"
                  f"               can start sending messages and files.\n"
                  f"   plain text: If you input only plain text, the program sends\n"
                  f"               it to the other node as a message.\n"
                  f"   ---\n"
                  f">> ", end="")
        else:
            print(f">> Command '{cmd}' is not a valid command\n>> ", end="")

    def listen(self):
        while not self.is_shutdown_event_set():
            try:
                # Set a timeout for the recvfrom operation
                self.get_socket().settimeout(1.0)  # 1.0 second timeout
                flag, seq_num, crc_check, data, src_addr = self.receive_packet()
                self.__keep_alive_retries = 0
                # Reset the timeout to None after a successful reception
                self.get_socket().settimeout(None)
            except socket.timeout:
                self.get_socket().settimeout(None)
                continue
            if crc_check is False:
                self.inc_curr_message_received_packets(12)
                continue
            if flag == 0:
                # syn
                self.inc_curr_message_received_packets(0)
                if self.is_connection_open():
                    print("Connection is already opened\n>> ", end="")
                    continue
                self.set_connection_open(True)
                # Start the keep-alive mechanism
                self.start_keep_alive()
            elif flag == 1:
                pass  # f_data
            elif flag == 2:
                pass  # data
            elif flag == 3:
                # ack
                self.inc_curr_message_received_packets(index=3)
                if seq_num == 0:
                    self.__response_received_event.set()
                self.update_message_status(seq_num=seq_num)
            elif flag == 4:
                # n_ack
                self.inc_curr_message_received_packets(index=4)
            elif flag == 5:
                # keep_alive
                # Reset the keep-alive timer
                self.inc_curr_message_received_packets(index=5)
                self.reset_keep_alive_timer()
            elif flag == 6:
                # switch
                self.inc_curr_message_received_packets(index=6)
                if self.is_switch_sent() is False:
                    self.send_packet(create_packet(flag=6, seq_num=seq_num, payload=b''))
                    self.inc_curr_message_sent_packets(index=6)
                    self.set_switch_sent(True)
                state = ("receiver",
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
                pass  # last
            elif flag == 11:
                pass  # init/zero packet

    def start_keep_alive(self) -> None:
        self.__keep_alive_timer = threading.Timer(TIMEOUT_INTERVAL_SENDER, self.keep_alive_timeout)
        self.__keep_alive_timer.start()

    def keep_alive_timeout(self) -> None:
        if self.is_shutdown_event_set():
            return
        if self.__keep_alive_retries < MAX_RETRIES:
            # print(">> Sending keep-alive message.\n>> ", end="")
            # Send keep-alive message
            self.send_packet(create_packet(flag=5, seq_num=0, payload=b''))
            self.inc_curr_message_sent_packets(index=5)
            self.__keep_alive_retries += 1
            # Restart the keep-alive timer
            self.start_keep_alive()
        else:
            print("Keep-alive timeout\n", end="")
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
