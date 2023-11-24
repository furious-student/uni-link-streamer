from abc import ABC, abstractmethod
import socket
from libscrc import ccitt_false
import threading
import time
import requests

from typing import Literal, Union, Any, Tuple, List


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
    crc = calc_crc(payload)
    header = create_header(flag=flag, seq_num=seq_num, crc=crc)
    packet = add_header(header=header, payload=payload)
    return packet


def calc_crc(fragment_data: bytes) -> int:
    return ccitt_false(fragment_data)


def check_crc(crc_received: int, packet_received: bytes) -> bool:
    return crc_received == calc_crc(packet_received)


def is_command(input_message: str) -> Tuple[bool, str, List[str]]:
    words = input_message.split(" ")
    first_word = words[0]
    other_words = words[1:]
    # if the last character of the first word is exclamation mark, the command, other words (arguments)
    return first_word[-1] == "!", first_word, other_words


def text_input() -> str:
    message = input(">> ")
    return message


class NodeType(ABC):
    __dst_address: Tuple[str, int]
    __node_socket: socket

    def __init__(self, dst_ip: Union[str, int], dst_port: int):
        self.__dst_address = (dst_ip, dst_port)

    def set_dst_address(self, dst_ip: str, dst_port: int) -> None:
        self.__dst_address = (dst_ip, dst_port)

    def set_socket(self, node_socket) -> None:
        self.__node_socket = node_socket

    def get_dst_address(self) -> Tuple[str, int]:
        return self.__dst_address

    def get_socket(self) -> socket:
        return self.__node_socket

    @abstractmethod
    def start(self) -> None:
        pass

    @abstractmethod
    def send_packet(self, packet: bytes) -> None:
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
