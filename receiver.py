import socket
from abc import ABC
from typing import Tuple

from node_type import *


class Receiver(NodeType, ABC):
    __src_address: Tuple[str, int]

    def __init__(self, src_ip: str, src_port: int):
        super().__init__("", -1)
        self.__src_address = (src_ip, src_port)

    def set_dst_address(self, dst_ip, dst_port):
        super().set_dst_address(dst_ip=dst_ip, dst_port=dst_port)

    def send_packet(self, packet: bytes) -> None:
        pass

    def start(self) -> None:
        # Create a UDP socket
        super().set_socket(socket.socket(socket.AF_INET,      # Internet
                                         socket.SOCK_DGRAM))  # UDP
        self.get_socket().bind(self.__src_address)
        print(">> Receiver is up")
        print(f">> Receiver listens on {self.__src_address}")
        print(">> To display all available commands, type 'help!'")
        self.listen()

    def listen_input(self) -> str:
        message = input()
        return message

    def handle_cmd(self, cmd: str, arg: str) -> None:
        pass

    def keep_alive(self) -> None:
        pass

    def send_message(self, message: str):
        self.__node_socket.sendto(message.encode("utf-8"), self.__dst_address)
        if message[0] != "I":
            print(">> ", end="")

    def listen(self):
        my_socket: socket = self.get_socket()
        waiting = True
        while waiting:
            response, _ = my_socket.recvfrom(1472)
            flag, seq_num, crc = parse_header(response[:6])
            data = response[6:].decode(encoding="utf-8")
            # crc_check = check_crc(crc, data)
            if flag == 0:
                pass  # syn
            elif flag == 1:
                pass  # f_data
            elif flag == 2:
                # data
                print(f">> frag: {seq_num} | data: {data}")
            elif flag == 3:
                pass  # ack
            elif flag == 4:
                pass  # n_ack
            elif flag == 5:
                pass  # keep_alive
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

