from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

key = RSA.generate(2048)
public_key = key.publickey()

private_key_pem = key.export_key()
public_key_pem = public_key.export_key()

private_key = RSA.import_key(private_key_pem)
public_key = RSA.import_key(public_key_pem)

message = "Asymmetric Encryption"
cipher = PKCS1_OAEP.new(public_key)
ciphertext = cipher.encrypt(message.encode())

cipher = PKCS1_OAEP.new(private_key)
decrypted_message = cipher.decrypt(ciphertext).decode()

print("Original Message:", message)
print("Encrypted Message:", ciphertext.hex())
print("Decrypted Message:", decrypted_message)