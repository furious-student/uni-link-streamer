from abc import ABC, abstractmethod
import socket
from libscrc import ccitt_false
import threading

from typing import Tuple, List, Union


def parse_header(header: bytes) -> Tuple[int, int, int]:
    if len(header) != 6:
        raise ValueError(f"The 'header' argument must have a length of 4 but has {len(header)}")
    num_header = int.from_bytes(header[:4], byteorder='big', signed=False)
    num_crc = int.from_bytes(header[4:], byteorder='big', signed=False)

    # Get the first 4 bits (flag) from the header:
    flags = num_header & 0b11110000_00000000_00000000_00000000
    # Right shift it 28 times to obtain the original 4-bit long flag:
    flags = flags >> 28
    # Get the last 28 bits (seq_num) from the header:
    seq_num = num_header & 0b00001111_11111111_11111111_11111111
    return flags, seq_num, num_crc


def create_header(flag: int, seq_num: int, crc: int) -> bytes:
    if not isinstance(flag, int) or flag < 0 or flag > 15:
        raise ValueError(f"The 'flag' argument has to be integer from interval <0;15> but is {flag}")
    if not isinstance(seq_num, int) or seq_num < 0 or seq_num > 268_435_455:
        raise ValueError(f"The 'seq_num' argument has to be integer from interval <0;268435455> but is {seq_num}")
    # The x's represent the actual flag value: flag = 0b00000000_00000000_00000000_0000xxxx
    # And we need to put it here:              flag = 0bxxxx0000_00000000_00000000_00000000
    # Therefore need to perform 28 byte shifts to the left
    flag = flag << 28

    # Then we perform a bitwise or to create the header:  flag    = xxxx0000_00000000_00000000_00000000
    #                                                     seq_num = 0000yyyy_yyyyyyyy_yyyyyyyy_yyyyyyyy
    #                                                     header  = xxxxyyyy_yyyyyyyy_yyyyyyyy_yyyyyyyy
    header = flag | seq_num
    header = header.to_bytes(length=4, byteorder="big", signed=False) + crc.to_bytes(length=2,
                                                                                     byteorder="big",
                                                                                     signed=False)
    return header


def add_header(header: bytes, payload: bytes) -> bytes:
    return header + payload


def create_packet(flag: int, seq_num: int, payload: bytes) -> bytes:
    header_no_crc = ((flag << 28) | seq_num).to_bytes(length=4, byteorder="big", signed=False)
    crc = calc_crc(header_no_crc + payload)
    header = create_header(flag=flag, seq_num=seq_num, crc=crc)
    packet = add_header(header=header, payload=payload)
    return packet


def print_packet(flag: int, seq_num: int, crc_check: int, payload: bytes):
    print(f"flag: {flag} | seq_num: {seq_num} | crc_check: {crc_check} | "
          f"payload_size: {len(payload)}B + header_size: 6B")
    if flag == 0:
        print(">> ", end="")


def corrupt_packet(packet: bytes) -> bytes:
    header = packet[:6]
    payload = packet[6:]
    corrupted_byte = bytes([(payload[0] + 10) % 256])
    payload = corrupted_byte + payload[1:]
    return header + payload


def calc_crc(fragment_data: bytes) -> int:
    return ccitt_false(fragment_data)


def check_crc(crc_received: int, packet_received: bytes) -> bool:
    return crc_received == calc_crc(packet_received)


def is_command(input_message: str) -> Tuple[bool, str, str]:
    words = input_message.split(" ")
    first_word = words[0]
    if len(words) == 1:
        other_words = None
    else:
        other_words = " ".join(words[1:])
    # if the last character of the first word is exclamation mark, the command, other words (argument)
    return first_word[-1] == "!", first_word, other_words


def text_input() -> str:
    print(">> ", end="")
    message = input()
    return message


class NodeType(ABC):
    __dst_address: Tuple[str, int]
    __src_address: Tuple[str, int]
    __node_socket: socket.socket
    __curr_message_received_packets: List[int]
    __curr_message_sent_packets: List[int]
    __connection_open: bool
    __fin_sent: bool
    __switch_sent: bool
    __shutdown_event: threading.Event
    __switch_state: Union[None, Tuple[str, socket.socket, Tuple[str, int], Tuple[str, int], List[int], List[int]]]

    def __init__(self, dst_ip: str, dst_port: int, src_ip: str, src_port: int,
                 curr_message_received_packets: list[int] = None,
                 curr_message_sent_packets: list[int] = None,
                 connection_open: bool = False
                 ):
        self.__dst_address = (dst_ip, dst_port)
        self.__src_address = (src_ip, src_port)
        if curr_message_received_packets is None:
            self.__curr_message_received_packets = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        else:
            self.__curr_message_received_packets = curr_message_received_packets

        if curr_message_sent_packets is None:
            self.__curr_message_sent_packets = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        else:
            self.__curr_message_sent_packets = curr_message_sent_packets
        # Event to signal threads to gracefully terminate
        self.__shutdown_event = threading.Event()
        self.__connection_open = connection_open
        self.__fin_sent = False
        self.__switch_sent = False
        self.__switch_state = None

    def set_dst_address(self, dst_ip: str, dst_port: int) -> None:
        self.__dst_address = (dst_ip, dst_port)

    def set_src_address(self, src_ip: str, src_port: int):
        self.__src_address = (src_ip, src_port)

    def set_socket(self, node_socket) -> None:
        self.__node_socket = node_socket

    def set_connection_open(self, value: bool) -> None:
        self.__connection_open = value

    def set_fin_sent(self, value: bool) -> None:
        self.__fin_sent = value

    def set_switch_sent(self, value: bool) -> None:
        self.__switch_sent = value

    def set_switch_state(self,
                         value: Union[None, Tuple[str, socket.socket,
                                                  Tuple[str, int], Tuple[str, int],
                                                  List[int], List[int]]]) -> None:
        self.__switch_state = value

    def get_dst_address(self) -> Tuple[str, int]:
        return self.__dst_address

    def get_src_address(self) -> Tuple[str, int]:
        return self.__src_address

    def get_socket(self) -> socket.socket:
        return self.__node_socket

    def get_curr_message_received_packets(self) -> List[int]:
        return self.__curr_message_received_packets

    def get_curr_message_sent_packets(self) -> List[int]:
        return self.__curr_message_sent_packets

    def get_switch_state(self) -> Union[None, Tuple[str, socket.socket,
                                                    Tuple[str, int], Tuple[str, int],
                                                    List[int], List[int]]]:
        return self.__switch_state

    def is_shutdown_event_set(self) -> bool:
        return self.__shutdown_event.is_set()

    def is_connection_open(self) -> bool:
        return self.__connection_open

    def is_fin_sent(self) -> bool:
        return self.__fin_sent

    def is_switch_sent(self) -> bool:
        return self.__switch_sent

    def send_packet(self, packet: bytes) -> None:
        try:
            self.__node_socket.sendto(packet, self.get_dst_address())
        except OSError:
            return

    def receive_packet(self) -> Tuple[int, int, bool, bytes, Tuple[str, int]]:
        response, src_addr = self.__node_socket.recvfrom(1472)
        flag, seq_num, crc = parse_header(response[:6])
        data = response[6:]
        crc_check = check_crc(crc, response[:4] + response[6:])
        return flag, seq_num, crc_check, data, src_addr

    def shutdown(self, spaces: bool = False, soft: bool = False) -> None:
        if spaces is True:
            print("   ", end="")
        self.__connection_open = False
        # Set the shutdown event to signal other threads to terminate
        self.__shutdown_event.set()
        if soft is False:
            print("Shutting down...")
            print("   Connection closed\n"
                  ">> ", end="")

    def init_curr_message_received_packets(self) -> None:
        syns = self.__curr_message_received_packets[0]
        kas = self.__curr_message_received_packets[5]
        fins = self.__curr_message_received_packets[8]
        self.__curr_message_received_packets = [syns, 0, 0, 0, 0, kas, 0, 0, fins, 0, 0, 0, 0]

    def init_curr_message_sent_packets(self) -> None:
        syns = self.__curr_message_sent_packets[0]
        kas = self.__curr_message_sent_packets[5]
        fins = self.__curr_message_sent_packets[8]
        self.__curr_message_sent_packets = [syns, 0, 0, 0, 0, kas, 0, 0, fins, 0, 0, 0, 0]

    def print_sent_packet_stats(self) -> None:
        packets_stats = self.__curr_message_sent_packets
        ack_and_data = sum(packets_stats[1:5] + packets_stats[6:8] + packets_stats[9:])
        print(f"  Sent: {ack_and_data} packets (without syn, keep-alive and fin):\n"
              f"    {packets_stats[0]} SYN packets\n"
              f"    {packets_stats[11]} INIT packet\n"
              f"    {packets_stats[1] + packets_stats[2] + packets_stats[10]} DATA packets\n"
              f"    {packets_stats[3]} ACK packets\n"
              f"    {packets_stats[4]} N_ACK packets\n"
              f"    {packets_stats[5]} KEEP-ALIVE packets\n"
              f"    {packets_stats[8]} FIN packets")

    def print_received_packet_stats(self) -> None:
        packets_stats = self.__curr_message_received_packets
        ack_and_data = sum(packets_stats[1:5] + packets_stats[6:8] + packets_stats[9:])
        print(f"  Received: {ack_and_data} packets (without syn, keep-alive and fin):\n"
              f"    {packets_stats[0]} SYN packets\n"
              f"    {packets_stats[11]} INIT packet\n"
              f"    {packets_stats[1] + packets_stats[2] + packets_stats[10]} DATA packets\n"
              f"    {packets_stats[3]} ACK packets\n"
              f"    {packets_stats[4]} N_ACK packets\n"
              f"    {packets_stats[12]} corrupted packets\n"
              f"    {packets_stats[5]} KEEP-ALIVE packets\n"
              f"    {packets_stats[8]} FIN packets")

    def inc_curr_message_received_packets(self, index: int) -> None:
        self.__curr_message_received_packets[index] += 1

    def inc_curr_message_sent_packets(self, index: int) -> None:
        self.__curr_message_sent_packets[index] += 1

    @abstractmethod
    def start(self, soft: bool = False, node_socket: socket.socket = None) -> None:
        pass

    @abstractmethod
    def listen_input(self) -> None:
        pass

    @abstractmethod
    def listen(self) -> None:
        pass

    @abstractmethod
    def handle_cmd(self, cmd: str, arg: str) -> None:
        pass
