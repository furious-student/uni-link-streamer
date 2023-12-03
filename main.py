from typing import Union, Optional, Tuple, List
from sender import Sender
from receiver import Receiver
from node_crafter import create_sender, create_receiver
from input_checker import while_not_valid_ip, while_not_valid_number


def main():
    choice = None
    next_node: Union[None,
                     Optional[Receiver],
                     Optional["Sender"],
                     Tuple[str, Tuple[str, int], Tuple[str, int], List[int], List[int]]] = None
    while choice != "exit!":
        if next_node is None:
            choice = input("Input node type (sender|receiver) or 'exit!': ")
        else:
            node_type, node_socket, dst_addr, src_addr, received_packets, sent_packets = next_node
            if node_type == "sender":
                print(">> Switching roles...")
                next_node = create_sender(dst_addr=dst_addr,
                                          src_addr=src_addr,
                                          curr_message_received_packets=received_packets,
                                          curr_message_sent_packets=sent_packets)
            elif node_type == "receiver":
                print("Switching roles...")
                next_node = create_receiver(dst_addr=dst_addr,
                                            src_addr=src_addr,
                                            curr_message_received_packets=received_packets,
                                            curr_message_sent_packets=sent_packets)
            else:
                print(">> Error")
                next_node = None
                continue
            next_node = next_node.start(soft=True, node_socket=node_socket)
            continue
        if choice == "sender":
            src_ip = while_not_valid_ip("Source IP: ")
            src_port = while_not_valid_number("Source Port: ", lower=1024, upper=65535)
            dst_ip = while_not_valid_ip("Destination IP: ")
            dst_port = while_not_valid_number("Destination Port: ", lower=1024, upper=65535)
            node = Sender(dst_ip=dst_ip, dst_port=int(dst_port), src_ip=src_ip, src_port=int(src_port))
            next_node = node.start()
        elif choice == "receiver":
            ip = while_not_valid_ip("Source IP: ")
            port = while_not_valid_number("Source Port: ", lower=1024, upper=65535)
            node = Receiver(src_ip=ip, src_port=int(port))
            next_node = node.start()


if __name__ == '__main__':
    main()
