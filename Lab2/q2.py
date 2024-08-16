from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

key = b'0123456789ABCDEF0123456789ABCDEF'
message = b'Sensitive Information'

cipher = AES.new(key, AES.MODE_ECB)

padded_message = pad(message, AES.block_size)

ciphertext = cipher.encrypt(padded_message)

print("Ciphertext:", ciphertext.hex())

decipher = AES.new(key, AES.MODE_ECB)
decrypted_padded_message = decipher.decrypt(ciphertext)

decrypted_message = unpad(decrypted_padded_message, AES.block_size)

print("Decrypted message:", decrypted_message.decode())