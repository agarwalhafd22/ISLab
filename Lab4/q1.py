from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15

class KeyManager:
    def __init__(self):
        self.keys = {}

    def generate_rsa_key(self, system_id):
        key = RSA.generate(2048)
        self.keys[system_id] = {
            'private': key,
            'public': key.publickey()
        }
        return self.keys[system_id]['public']

    def get_public_key(self, system_id):
        return self.keys[system_id]['public']

    def get_private_key(self, system_id):
        return self.keys[system_id]['private']

    def revoke_key(self, system_id):
        if system_id in self.keys:
            del self.keys[system_id]

class SecureSystem:
    def __init__(self, system_id, key_manager):
        self.system_id = system_id
        self.key_manager = key_manager
        self.key_manager.generate_rsa_key(self.system_id)

    def encrypt_message(self, recipient_id, message):
        recipient_public_key = self.key_manager.get_public_key(recipient_id)
        session_key = get_random_bytes(16)
        
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
        
        return enc_session_key + cipher_aes.nonce + tag + ciphertext

    def decrypt_message(self, encrypted_data):
        private_key = self.key_manager.get_private_key(self.system_id)
        enc_session_key = encrypted_data[:private_key.size_in_bytes()]
        nonce = encrypted_data[private_key.size_in_bytes():private_key.size_in_bytes()+16]
        tag = encrypted_data[private_key.size_in_bytes()+16:private_key.size_in_bytes()+32]
        ciphertext = encrypted_data[private_key.size_in_bytes()+32:]
        
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(enc_session_key)
        
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        return data.decode('utf-8')

    def sign_document(self, document):
        private_key = self.key_manager.get_private_key(self.system_id)
        hash_obj = SHA256.new(document.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return signature

    def verify_signature(self, document, signature, signer_id):
        public_key = self.key_manager.get_public_key(signer_id)
        hash_obj = SHA256.new(document.encode('utf-8'))
        try:
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            return True
        except (ValueError, TypeError):
            return False

def simulate_communication():
    key_manager = KeyManager()
    
    system_a = SecureSystem("Finance", key_manager)
    system_b = SecureSystem("HR", key_manager)
    system_c = SecureSystem("SupplyChain", key_manager)
    
    # Simulate secure communication
    message = "Confidential financial report"
    encrypted_message = system_a.encrypt_message("HR", message)
    decrypted_message = system_b.decrypt_message(encrypted_message)
    print(f"Original message: {message}")
    print(f"Decrypted message: {decrypted_message}")
    
    # Simulate document signing
    document = "Employee contract for Alice"
    signature = system_b.sign_document(document)
    is_valid = system_a.verify_signature(document, signature, "HR")
    print(f"Document: {document}")
    print(f"Signature valid: {is_valid}")

if __name__ == "__main__":
    simulate_communication()
