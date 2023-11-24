from abc import ABC
import socket
from typing import Dict

from node_type import *


def add_header(header: bytes, payload: bytes) -> bytes:
    return header + payload


def message_to_bytes(message: str) -> bytes:
    return message.encode(encoding="utf-8")


def file_input(file_name: str) -> bytes:
    file = open(file_name, mode='rb')  # b means binary
    file_data = file.read()
    return file_data


class Sender(NodeType, ABC):
    __curr_message_status: Dict[int, bool]
    __frag_size: int

    def __init__(self, dst_ip: str, dst_port: int):
        super().__init__(dst_ip, dst_port)
        self.__curr_message_status = dict()
        self.__frag_size = 10

    def start(self) -> None:
        super().set_socket(socket.socket(socket.AF_INET,      # Internet
                                         socket.SOCK_DGRAM))  # UDP
        print(">> Sender is up")
        print(f">> Messages will be send over to {self.get_dst_address()}")
        print(">> To display all available commands, type 'help!'")
        while True:
            self.listen_input()

    def fragment_data(self, data: bytes) -> List[bytes]:
        # Calculate the number of fragments needed
        frag_num = len(data) // self.__frag_size + (len(data) % self.__frag_size != 0)
        fragments = [data[i*self.__frag_size:(i+1)*self.__frag_size] for i in range(frag_num)]
        return fragments

    def map_fragments(self, fragments: List[bytes]) -> None:
        for seq_num, frag in enumerate(fragments):
            self.__curr_message_status.update({seq_num: False})

    def create_data_packets(self, data: bytes) -> List[bytes]:
        flag = 2  # flag 2 = DATA
        data_fragments = self.fragment_data(data=data)
        self.map_fragments(data_fragments)
        packets = list()
        for seq_num, frag in enumerate(data_fragments):
            crc = calc_crc(frag)
            header = create_header(flag=flag, seq_num=seq_num, crc=crc)
            packet = add_header(header=header, payload=frag)
            packets.append(packet)
        return packets

    def send_packet(self, packet: bytes) -> None:
        self.get_socket().sendto(packet, self.get_dst_address())

    def send_all_packets(self, packets: List[bytes]) -> None:
        for pkt in packets:
            self.send_packet(pkt)

    def send_file_data(self) -> None:
        seq_num = 0
        pass

    def listen_input(self) -> None:
        input_message = text_input()
        # if sending is in process, display error
        command = is_command(input_message)
        if command[0]:
            cmd = command[1]
            args = command[2]
            self.handle_cmd(cmd=cmd, arg=args[0])
        else:
            b_message = message_to_bytes(input_message)
            data_packets = self.create_data_packets(data=b_message)
            self.send_all_packets(data_packets)

    def handle_cmd(self, cmd: str, arg: str) -> None:
        if cmd == "file!":
            b_file = file_input(file_name=arg)
        elif cmd == "switch!":
            pass
        elif cmd == "end!":
            pass
        elif cmd == "f_size!":
            pass

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
                pass  # data
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
