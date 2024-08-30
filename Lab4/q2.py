import os
import time
import json
import logging
from typing import Tuple, Dict
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

class RabinCryptosystem:
    @staticmethod
    def generate_key_pair(key_size: int = 1024) -> Tuple[int, int, int]:
        logging.info(f"Generating Rabin key pair with size {key_size}")
        p = number.getPrime(key_size // 2)
        q = number.getPrime(key_size // 2)
        while p % 4 != 3 or q % 4 != 3:
            p = number.getPrime(key_size // 2)
            q = number.getPrime(key_size // 2)
        n = p * q
        logging.info("Rabin key pair generated successfully")
        return n, p, q

    @staticmethod
    def encrypt(public_key: int, message: bytes) -> int:
        m = int.from_bytes(message, 'big')
        return pow(m, 2, public_key)

    @staticmethod
    def decrypt(p: int, q: int, ciphertext: int) -> bytes:
        n = p * q
        mp = pow(ciphertext, (p + 1) // 4, p)
        mq = pow(ciphertext, (q + 1) // 4, q)
        yp = pow(q, p - 2, p)
        yq = pow(p, q - 2, q)
        r = (yp * q * mp + yq * p * mq) % n
        if pow(r, 2, n) == ciphertext:
            return r.to_bytes((r.bit_length() + 7) // 8, 'big')
        r = n - r
        if pow(r, 2, n) == ciphertext:
            return r.to_bytes((r.bit_length() + 7) // 8, 'big')
        r = (yp * q * mp - yq * p * mq) % n
        if pow(r, 2, n) == ciphertext:
            return r.to_bytes((r.bit_length() + 7) // 8, 'big')
        r = n - r
        if pow(r, 2, n) == ciphertext:
            return r.to_bytes((r.bit_length() + 7) // 8, 'big')
        raise ValueError("Decryption failed")

class KeyManagementService:
    def __init__(self, config_file: str = 'config.json'):
        self.config = self.load_config(config_file)
        self.keys: Dict[str, Dict] = {}
        self.setup_logging()
        logging.info("KeyManagementService initialized")

    def load_config(self, config_file: str) -> Dict:
        logging.info(f"Loading configuration from {config_file}")
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
            logging.info("Configuration loaded successfully")
            return config
        except FileNotFoundError:
            logging.error(f"Configuration file {config_file} not found")
            raise
        except json.JSONDecodeError:
            logging.error(f"Error decoding JSON in {config_file}")
            raise

    def setup_logging(self):
        logging.basicConfig(filename=self.config['log_file'], level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info("Logging setup complete")

    def generate_key_pair(self, facility_id: str) -> None:
        logging.info(f"Generating key pair for facility {facility_id}")
        key_size = self.config['key_size']
        n, p, q = RabinCryptosystem.generate_key_pair(key_size)
        expiration = datetime.now() + timedelta(days=self.config['key_validity_days'])
        
        self.keys[facility_id] = {
            'public_key': n,
            'private_key': (p, q),
            'expiration': expiration.isoformat()
        }
        
        self.secure_store_keys()
        logging.info(f"Generated new key pair for facility {facility_id}")

    def get_public_key(self, facility_id: str) -> int:
        if facility_id not in self.keys:
            logging.error(f"No keys found for facility {facility_id}")
            raise ValueError(f"No keys found for facility {facility_id}")
        return self.keys[facility_id]['public_key']

    def revoke_key(self, facility_id: str) -> None:
        if facility_id in self.keys:
            del self.keys[facility_id]
            self.secure_store_keys()
            logging.info(f"Revoked keys for facility {facility_id}")
        else:
            logging.warning(f"Attempted to revoke non-existent key for facility {facility_id}")

    def renew_keys(self) -> None:
        logging.info("Starting key renewal process")
        current_time = datetime.now()
        for facility_id, key_data in self.keys.items():
            expiration = datetime.fromisoformat(key_data['expiration'])
            if current_time >= expiration:
                self.generate_key_pair(facility_id)
                logging.info(f"Renewed keys for facility {facility_id}")
        logging.info("Key renewal process completed")

    def secure_store_keys(self) -> None:
        logging.info("Storing keys securely")
        encrypted_keys = {}
        for facility_id, key_data in self.keys.items():
            encrypted_keys[facility_id] = {
                'public_key': key_data['public_key'],
                'private_key': self.encrypt_private_key(key_data['private_key']),
                'expiration': key_data['expiration']
            }
        if encrypted_keys:
            with open(self.config['key_store_file'], 'w') as f:
                json.dump(encrypted_keys, f)
            logging.info("Stored keys securely")
        else:
            logging.warning("No keys to store")

    def load_keys(self) -> None:
        logging.info("Loading keys from secure storage")
        if os.path.exists(self.config['key_store_file']):
            try:
                with open(self.config['key_store_file'], 'r') as f:
                    file_content = f.read().strip()
                    if file_content:
                        encrypted_keys = json.loads(file_content)
                        for facility_id, key_data in encrypted_keys.items():
                            self.keys[facility_id] = {
                                'public_key': key_data['public_key'],
                                'private_key': self.decrypt_private_key(key_data['private_key']),
                                'expiration': key_data['expiration']
                            }
                        logging.info("Loaded keys from secure storage")
                    else:
                        logging.warning("Key store file is empty")
            except json.JSONDecodeError as e:
                logging.error(f"Error decoding JSON in key store: {str(e)}")
                logging.info("Treating as if no existing key store found")
            except Exception as e:
                logging.error(f"Unexpected error loading keys: {str(e)}")
        else:
            logging.warning("No existing key store found")

    def encrypt_private_key(self, private_key: Tuple[int, int]) -> str:
        key = RSA.generate(2048)
        cipher = PKCS1_OAEP.new(key)
        encrypted = cipher.encrypt(json.dumps(private_key).encode())
        return encrypted.hex()

    def decrypt_private_key(self, encrypted_key: str) -> Tuple[int, int]:
        key = RSA.generate(2048)
        cipher = PKCS1_OAEP.new(key)
        decrypted = cipher.decrypt(bytes.fromhex(encrypted_key))
        return tuple(json.loads(decrypted))

    def audit_log(self, operation: str, facility_id: str) -> None:
        logging.info(f"Operation: {operation}, Facility: {facility_id}")

    def run(self):
        logging.info("Starting KeyManagementService")
        self.load_keys()
        
        # Test run: Generate a key pair for a test facility
        test_facility_id = "TEST_FACILITY"
        self.generate_key_pair(test_facility_id)
        logging.info(f"Test key pair generated for {test_facility_id}")
        
        logging.info("Entering main loop")
        try:
            while True:
                self.renew_keys()
                time.sleep(self.config['check_interval'])
        except KeyboardInterrupt:
            logging.info("KeyManagementService stopped by user")
        except Exception as e:
            logging.error(f"An error occurred: {str(e)}")
        finally:
            logging.info("KeyManagementService shutting down")

if __name__ == "__main__":
    kms = KeyManagementService()
    kms.run()