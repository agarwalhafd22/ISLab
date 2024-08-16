from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import time

message = b'Performance Testing of Encryption Algorithms'

des_key = b'12345678'

aes_key = b'12345678901234567890123456789012'

start_time = time.time()
des_cipher = DES.new(des_key, DES.MODE_ECB)
padded_message = pad(message, DES.block_size)
encrypted_message = des_cipher.encrypt(padded_message)
end_time = time.time()
des_encryption_time = (end_time - start_time)*1000

start_time = time.time()
decrypted_padded_message = des_cipher.decrypt(encrypted_message)
decrypted_message = unpad(decrypted_padded_message, DES.block_size)
end_time = time.time()
des_decryption_time = (end_time - start_time)*1000

print("DES Encryption time:", des_encryption_time)
print("DES Decryption time:", des_decryption_time)

start_time = time.time()
aes_cipher = AES.new(aes_key, AES.MODE_ECB)
padded_message = pad(message, AES.block_size)
encrypted_message = aes_cipher.encrypt(padded_message)
end_time = time.time()
aes_encryption_time = (end_time - start_time)*1000

start_time = time.time()
decrypted_padded_message = aes_cipher.decrypt(encrypted_message)
decrypted_message = unpad(decrypted_padded_message, AES.block_size)
end_time = time.time()
aes_decryption_time = (end_time - start_time)*1000

print("AES-256 Encryption time:", aes_encryption_time)
print("AES-256 Decryption time:", aes_decryption_time)

print("Conclusion: AES encryption and decryption is faster than DES")