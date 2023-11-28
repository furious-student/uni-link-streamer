from receiver import Receiver
from sender import Sender


def create_sender(dst_addr, src_addr, curr_message_received_packets, curr_message_sent_packets):
    node = Sender(dst_ip=dst_addr[0], dst_port=dst_addr[1],
                  curr_message_received_packets=curr_message_received_packets,
                  curr_message_sent_packets=curr_message_sent_packets,
                  connection_open=True)
    node.set_src_address(src_ip=src_addr[0], src_port=src_addr[1])
    return node


def create_receiver(dst_addr, src_addr, curr_message_received_packets, curr_message_sent_packets):
    node = Receiver(src_ip=src_addr[0], src_port=src_addr[1],
                    curr_message_received_packets=curr_message_received_packets,
                    curr_message_sent_packets=curr_message_sent_packets,
                    connection_open=True)
    node.set_dst_address(dst_ip=dst_addr[0], dst_port=dst_addr[1])
    return node
