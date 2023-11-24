import socket
import threading
import time
# import requests

from typing import Literal, Union, Any, Tuple


# def get_public_ip():
#     try:
#         # Use a service that echoes the public IP address
#         response = requests.get('https://api64.ipify.org?format=json')
#         if response.status_code == 200:
#             data = response.json()
#             return data['ip']
#         else:
#             return "Unable to retrieve public IP"
#     except Exception as e:
#         return f"Error: {e}"


class Node:
    __role: Literal["sender", "receiver"]
    __node_socket: socket
    __src_address: Tuple[Union[str, int], int]
    __dst_address: Tuple[Union[str, int], int]

    def __init__(self, role: Literal["sender", "receiver"] = "sender"):
        self.__role = role

    # --------------------------------- GETTERS AND SETTERS ----------------------------------
    def get_role(self) -> Literal["sender", "receiver"]:
        return self.__role

    def set_src_address(self, manual_ip: bool = False, ip: Union[str, int] = "localhost", port: int = -1) -> None:
        if manual_ip:
            self.__src_address = (ip, port)
        else:
            try:
                src_ip = socket.gethostbyname(socket.gethostname())
            except socket.gaierror:
                src_ip = "127.0.0.1"
                # src_ip = get_public_ip()
            self.__src_address = (src_ip, port)
        print(f">> Node's ip address set to {self.__src_address[0]}, port no. {self.__src_address[1]}")

    def set_dst_address(self, ip: Union[str, int] = "localhost", port: int = -1) -> None:
        self.__dst_address = (ip, port)
    # ----------------------------------------------------------------------------------------

    def start(self) -> None:
        # Create a UDP socket
        self.__node_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.__node_socket.bind(self.__src_address)
        if self.__role == "sender":
            print(f">> Now you can write your message that will be send to "
                  f"({self.__dst_address[0]}:{self.__dst_address[1]})"
                  f"\n>> ", end="")
            self.listen_input()
        else:
            print(f">> Node started listening on ({self.__src_address[0]}:{self.__src_address[1]})"
                  f"\n>> ", end="")
            self.listen()

    def switch_role(self) -> None:
        self.__role = "sender" if self.__role == "receiver" else "receiver"  # type: ignore

    def send_message(self, message: str):
        self.__node_socket.sendto(message.encode("utf-8"), self.__dst_address)
        if message[0] != "I":
            print(">> ", end="")

    def send_file(self):
        pass

    def keep_alive(self):
        pass

    def listen(self):
        waiting = True
        while waiting:
            response, _ = self.__node_socket.recvfrom(1024)
            readable_resp = response.decode('utf-8')
            print(f"Received from ({self.__dst_address[0]}:{self.__dst_address[1]}): {readable_resp}"
                  f"\n>> ",
                  end="")
            if readable_resp[0] != "I":
                self.send_message(f"I received your message '{readable_resp}'")
            if readable_resp == "switch()":
                self.switch_role()
                print("I am 'sender' now"
                      "\n>> ", end="")
            if response is not None:
                waiting = False
        self.listen_input()

    def listen_input(self):
        if self.__role == "receiver":
            self.listen()
            return
        message = input()
        if message == "switch()":
            self.switch_role()
            print(">> I am a 'receiver' now")
        # message to bytes -> fragments -> send one fragment and listen for ack
        self.send_message(message=message)
        self.listen()

