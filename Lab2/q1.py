from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

key = b'A1B2C3D4'
plain_text = b'Confidential Data'

cipher = DES.new(key, DES.MODE_ECB)
padded_message = pad(plain_text, DES.block_size)
encrypted_message = cipher.encrypt(padded_message)

print("Encrypted message:", encrypted_message.hex())

decrypted_padded_message = cipher.decrypt(encrypted_message)
decrypted_message = unpad(decrypted_padded_message, DES.block_size)

print("Decrypted message:", decrypted_message.decode())