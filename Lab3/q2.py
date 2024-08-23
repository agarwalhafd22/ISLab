from ecies.utils import generate_eth_key, generate_key
from ecies import encrypt, decrypt
eth_k = generate_eth_key()
sk_hex = eth_k.to_hex()  # hex string
pk_hex = eth_k.public_key.to_hex()  # hex string
data = b'Secure Transactions'
print("Original: ",data.decode())
print("Encrypted: ",encrypt(pk_hex, data).hex())
print("Decrypted: ",decrypt(sk_hex, encrypt(pk_hex, data)).decode())
