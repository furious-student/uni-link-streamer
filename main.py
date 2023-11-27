from typing import Union, List, Optional
import socket

from node_type import parse_header, create_header
from receiver import Receiver
from sender import Sender


def main():
    node_type = input("Input node type (sender|receiver): ")
    node: Union[Optional["Sender"], Optional["Receiver"]]
    if node_type == "sender":
        ip = input("Destination IP: ")
        port = input("Destination Port: ")
        node = Sender(dst_ip=ip, dst_port=int(port))
        node.start()
    elif node_type == "receiver":
        ip = input("Source IP: ")
        port = input("Source Port: ")
        node = Receiver(src_ip=ip, src_port=int(port))
        node.start()

    # flag = 15
    # seq_num = 268_000_000
    # crc = 5
    # print(f"Original input values: flag={flag}, seq_num={seq_num}, crc={crc}")
    #
    # bts = create_header(flag=flag, seq_num=seq_num, crc=crc)
    # print(f"In-byte values: flag={bts.hex()[:1]}, seq_num={bts.hex()[1:6]}, crc={bts.hex()[6:]}")
    # print(f"Bytes: {len(bts)}")
    #
    # header = parse_header(header=bts)
    # print(f"Parsed byte values: flag={header[0]}, seq_num={header[1]}, crc={header[2]}")


def try_to_int(value_to_int: str) -> Union[str, int]:
    original_src_ip = value_to_int
    try:
        output = int(original_src_ip)
    except ValueError:
        output = original_src_ip
    return output


def prettify_hex(hex_str: str) -> str:
    return_str = ""
    for byte in range(0, len(hex_str), 2):
        return_str += str(byte) + " "
    return return_str


if __name__ == '__main__':
    main()
