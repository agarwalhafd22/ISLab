import socket

def custom_hash(input_string):
    hash_value = 5381
    for char in input_string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        hash_value &= 0xFFFFFFFF 
    return hash_value

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 65432))
server_socket.listen(1)
print("Server is listening on port 65432...")

conn, addr = server_socket.accept()
print(f"Connected by {addr}")

data = conn.recv(1024).decode()
print(f"Received data from client: {data}")

server_hash = custom_hash(data)
print(f"Computed hash on server: {server_hash}")

conn.send(str(server_hash).encode())

conn.close()
