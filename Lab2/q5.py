from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'FEDCBA9876543210FEDCBA9876543210'

message = b'Top Secret Data'
padded_message = pad(message, AES.block_size)

cipher = AES.new(key, AES.MODE_ECB)

encrypted_message = cipher.encrypt(padded_message)

print("Encrypted message:", encrypted_message.hex())

decrypted_padded_message = cipher.decrypt(encrypted_message)
decrypted_message = unpad(decrypted_padded_message, AES.block_size)

print("Decrypted message:", decrypted_message.decode())
