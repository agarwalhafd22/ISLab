import socket

def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        hash_value &= 0xFFFFFFFF 
    return hash_value

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(('localhost', 65432))

data_to_send = input("Enter the data to send to the server: ")
print(f"Data to send: {data_to_send}")

client_hash = custom_hash(data_to_send)
print(f"Computed hash on client: {client_hash}")

client_socket.send(data_to_send.encode())

received_hash = int(client_socket.recv(1024).decode())
print(f"Received hash from server: {received_hash}")

if client_hash == received_hash:
    print("Hashes match!")
else:
    print("Hashes do not match!")

client_socket.close()
