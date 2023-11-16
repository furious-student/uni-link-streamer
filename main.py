from typing import Union, List
import socket

from node import Node


def main():
    # host_name = socket.gethostname()
    # host_ip = socket.gethostbyname(host_name)

    role = input("Role (sender|receiver): ")
    node = Node(role=role)  # type: ignore

    src_ip: str = input("Source port: ")
    src_port = try_to_int(src_ip)
    node.set_src_address(port=src_port)

    dst: List[str] = input("Destination ip and port separated with semicolon (ip:port): ").split(":")
    dst_ip = try_to_int(dst[0])
    dst_port = try_to_int(dst[1])
    node.set_dst_address(ip=dst_ip, port=dst_port)

    node.start()


def try_to_int(value_to_int: str) -> Union[str, int]:
    original_src_ip = value_to_int
    try:
        output = int(original_src_ip)
    except ValueError:
        output = original_src_ip
    return output


if __name__ == '__main__':
    main()
