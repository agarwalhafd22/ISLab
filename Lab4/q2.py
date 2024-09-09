import os, time, json, logging
from typing import Tuple, Dict
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256

class RabinCryptosystem:
    @staticmethod
    def generate_key_pair(key_size: int = 1024) -> Tuple[int, int, int]:
        p = q = number.getPrime(key_size // 2)
        while p % 4 != 3 or q % 4 != 3:
            p = q = number.getPrime(key_size // 2)
        return p * q, p, q

    @staticmethod
    def encrypt(public_key: int, message: bytes) -> int:
        return pow(int.from_bytes(message, 'big'), 2, public_key)

    @staticmethod
    def decrypt(p: int, q: int, ciphertext: int) -> bytes:
        n, r = p * q, (p + 1) // 4
        mp, mq = pow(ciphertext, r, p), pow(ciphertext, r, q)
        yp, yq = pow(q, p - 2, p), pow(p, q - 2, q)
        for r in [(yp * q * mp + yq * p * mq) % n, n - _, (yp * q * mp - yq * p * mq) % n, n - _]:
            if pow(r, 2, n) == ciphertext:
                return r.to_bytes((r.bit_length() + 7) // 8, 'big')
        raise ValueError("Decryption failed")

class KeyManagementService:
    def __init__(self, config_file: str = 'config.json'):
        self.config = self.load_config(config_file)
        self.keys: Dict[str, Dict] = {}
        logging.basicConfig(filename=self.config['log_file'], level=logging.INFO,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        logging.info("KeyManagementService initialized")

    def load_config(self, config_file: str) -> Dict:
        try:
            with open(config_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logging.error(f"Error loading config: {str(e)}")
            raise

    def generate_key_pair(self, facility_id: str) -> None:
        n, p, q = RabinCryptosystem.generate_key_pair(self.config['key_size'])
        expiration = datetime.now() + timedelta(days=self.config['key_validity_days'])
        self.keys[facility_id] = {
            'public_key': n, 'private_key': (p, q), 'expiration': expiration.isoformat()
        }
        self.secure_store_keys()
        logging.info(f"Generated new key pair for facility {facility_id}")

    def get_public_key(self, facility_id: str) -> int:
        if facility_id not in self.keys:
            raise ValueError(f"No keys found for facility {facility_id}")
        return self.keys[facility_id]['public_key']

    def revoke_key(self, facility_id: str) -> None:
        if facility_id in self.keys:
            del self.keys[facility_id]
            self.secure_store_keys()
            logging.info(f"Revoked keys for facility {facility_id}")

    def renew_keys(self) -> None:
        for facility_id, key_data in self.keys.items():
            if datetime.now() >= datetime.fromisoformat(key_data['expiration']):
                self.generate_key_pair(facility_id)

    def secure_store_keys(self) -> None:
        encrypted_keys = {f: {**k, 'private_key': self.encrypt_private_key(k['private_key'])} 
                          for f, k in self.keys.items()}
        with open(self.config['key_store_file'], 'w') as f:
            json.dump(encrypted_keys, f)

    def load_keys(self) -> None:
        if os.path.exists(self.config['key_store_file']):
            try:
                with open(self.config['key_store_file'], 'r') as f:
                    encrypted_keys = json.load(f)
                self.keys = {f: {**k, 'private_key': self.decrypt_private_key(k['private_key'])} 
                             for f, k in encrypted_keys.items()}
            except Exception as e:
                logging.error(f"Error loading keys: {str(e)}")

    def encrypt_private_key(self, private_key: Tuple[int, int]) -> str:
        key = RSA.generate(2048)
        return PKCS1_OAEP.new(key).encrypt(json.dumps(private_key).encode()).hex()

    def decrypt_private_key(self, encrypted_key: str) -> Tuple[int, int]:
        key = RSA.generate(2048)
        return tuple(json.loads(PKCS1_OAEP.new(key).decrypt(bytes.fromhex(encrypted_key))))

    def run(self):
        logging.info("Starting KeyManagementService")
        self.load_keys()
        self.generate_key_pair("TEST_FACILITY")
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
    KeyManagementService().run()



# output
# 2024-09-09 10:00:00 - INFO - KeyManagementService initialized
# 2024-09-09 10:00:00 - INFO - Starting KeyManagementService
# 2024-09-09 10:00:00 - INFO - Generated new key pair for facility TEST_FACILITY
# 2024-09-09 10:10:00 - INFO - Generated new key pair for facility TEST_FACILITY
# 2024-09-09 10:20:00 - INFO - Generated new key pair for facility TEST_FACILITY
# ...
# 2024-09-09 23:50:00 - INFO - Generated new key pair for facility TEST_FACILITY
# 2024-09-10 00:00:00 - INFO - KeyManagementService stopped by user
# 2024-09-10 00:00:00 - INFO - KeyManagementService shutting down
