import socket
import os


def send_message(socket, message, address):
    socket.sendto(message.encode('utf-8'), address)


def send_file(socket, file_path, address):
    with open(file_path, 'rb') as file:
        file_data = file.read(1024)
        while file_data:
            socket.sendto(file_data, address)
            file_data = file.read(1024)


def receive_file(socket, file_path):
    with open(file_path, 'wb') as file:
        while True:
            file_data, _ = socket.recvfrom(1024)
            if not file_data:
                break
            file.write(file_data)


# Create a UDP socket
peer_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind the socket to a specific address and port
listen_addr = input("Input listening address:")
local_address = ('localhost', int(listen_addr))
peer_socket.bind(local_address)

print('Peer is listening on {}:{}'.format(*local_address))

# Get the peer's address
remote_address = input('Enter the other peer\'s address (e.g., localhost:12346): ')
remote_address = remote_address.split(':')
remote_address = (remote_address[0], int(remote_address[1]))

while True:
    # Get user input
    user_input = input('Enter message or file path to send: ')

    # Check if the user wants to send a file
    if os.path.isfile(user_input):
        send_message(peer_socket, 'file', remote_address)
        send_file(peer_socket, user_input, remote_address)
        print('File sent successfully.')
    else:
        send_message(peer_socket, user_input, remote_address)

    # Receive response from the other peer
    response, _ = peer_socket.recvfrom(1024)

    # Check if the response indicates a file
    if response.decode('utf-8') == 'file':
        file_path = input('Enter the file path to save the received file: ')
        receive_file(peer_socket, file_path)
        print('File received successfully.')
    else:
        print('Received from {}: {}'.format(remote_address, response.decode('utf-8')))
