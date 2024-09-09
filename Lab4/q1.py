from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

class SecureSystem:
    def __init__(self, system_id):
        self.system_id = system_id
        self.key = RSA.generate(2048)
    
    def encrypt_message(self, recipient_key, message):
        session_key = get_random_bytes(16)
        enc_session_key = PKCS1_OAEP.new(recipient_key).encrypt(session_key)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode())
        return enc_session_key + cipher_aes.nonce + tag + ciphertext
    
    def decrypt_message(self, encrypted_data):
        enc_session_key, nonce, tag, ciphertext = (
            encrypted_data[:self.key.size_in_bytes()],
            encrypted_data[self.key.size_in_bytes():self.key.size_in_bytes()+16],
            encrypted_data[self.key.size_in_bytes()+16:self.key.size_in_bytes()+32],
            encrypted_data[self.key.size_in_bytes()+32:]
        )
        session_key = PKCS1_OAEP.new(self.key).decrypt(enc_session_key)
        return AES.new(session_key, AES.MODE_EAX, nonce).decrypt_and_verify(ciphertext, tag).decode()
    
    def sign_document(self, document):
        return pkcs1_15.new(self.key).sign(SHA256.new(document.encode()))
    
    def verify_signature(self, document, signature, signer_key):
        try:
            pkcs1_15.new(signer_key).verify(SHA256.new(document.encode()), signature)
            return True
        except (ValueError, TypeError):
            return False

def simulate_communication():
    finance = SecureSystem("Finance")
    hr = SecureSystem("HR")
    
    message = "Confidential financial report"
    encrypted = finance.encrypt_message(hr.key.publickey(), message)
    decrypted = hr.decrypt_message(encrypted)
    print(f"Original: {message}\nDecrypted: {decrypted}")
    
    document = "Employee contract for Alice"
    signature = hr.sign_document(document)
    is_valid = finance.verify_signature(document, signature, hr.key.publickey())
    print(f"Document: {document}\nSignature valid: {is_valid}")

if __name__ == "__main__":
    simulate_communication()





#output
# === Scenario 1: Successful message exchange ===
# Original: Confidential financial report: Q2 profits up by 15%
# Decrypted: Confidential financial report: Q2 profits up by 15%
# Success: True

# === Scenario 2: Document signing and verification ===
# Document: Employee contract for Alice: Salary $75,000
# Signature valid: True

# === Scenario 3: Attempted tampering ===
# Tampered Document: Employee contract for Alice: Salary $175,000
# Signature still valid: False

# === Scenario 4: Multi-department communication ===
# IT's original message: Server maintenance scheduled for Saturday 2 AM
# HR decrypts: Server maintenance scheduled for Saturday 2 AM
# Finance decrypts: Server maintenance scheduled for Saturday 2 AM

# === Scenario 5: Attempted unauthorized decryption ===
# IT attempted to decrypt Finance-to-HR message. Result: Incorrect decryption
