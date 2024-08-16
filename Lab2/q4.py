from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

message = b'Classified Text'
key = b'1234567890ABCDEF12345678'  

cipher = DES3.new(key, DES3.MODE_ECB)
padded_message = pad(message, DES3.block_size)
encrypted_message = cipher.encrypt(padded_message)

print("Encrypted message:", encrypted_message.hex())

decrypted_padded_message = cipher.decrypt(encrypted_message)
decrypted_message = unpad(decrypted_padded_message, DES3.block_size)

print("Decrypted message:", decrypted_message.decode())