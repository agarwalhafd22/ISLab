from Crypto.PublicKey import DSA
from Crypto.Random import random
from Crypto.Hash import SHA256
import time

def generate_key_pair():
    key = DSA.generate(2048)
    private_key = key.x
    public_key = key.y
    return private_key, public_key, key

def compute_shared_secret(their_public_key, my_private_key, params):
    shared_secret = pow(their_public_key, my_private_key, params.p)
    return shared_secret

def main():
    print("Generating keys for Alice...")
    start_time = time.time()
    priv_key_A, pub_key_A, params_A = generate_key_pair()
    key_gen_time_A = time.time() - start_time
    print("Alice key generation time: ",key_gen_time_A)

    print("Generating keys for Bob...")
    start_time = time.time()
    priv_key_B, pub_key_B, params_B = generate_key_pair()
    key_gen_time_B = time.time() - start_time
    print("Bob key generation time: ",key_gen_time_B)

    params = params_A

    print("Computing shared secrets...")
    start_time = time.time()
    shared_secret_A = compute_shared_secret(pub_key_B, priv_key_A, params)
    shared_secret_time_A = time.time() - start_time
    print("Alice shared secret computation time: ",shared_secret_time_A)

    start_time = time.time()
    shared_secret_B = compute_shared_secret(pub_key_A, priv_key_B, params)
    shared_secret_time_B = time.time() - start_time
    print("Bob shared secret computation time: ",shared_secret_time_B)


if __name__ == "__main__":
    main()
