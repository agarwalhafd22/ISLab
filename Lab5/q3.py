import hashlib
import time
import secrets
from collections import defaultdict

def generate_random_string(length):
    return ''.join(secrets.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(length))

def compute_hash(input_string, algorithm):
    if algorithm == 'md5':
        return hashlib.md5(input_string.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(input_string.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(input_string.encode()).hexdigest()

def measure_hash_time(strings, algorithm):
    start_time = time.time()
    hashes = [compute_hash(s, algorithm) for s in strings]
    end_time = time.time()
    return hashes, end_time - start_time

def detect_collisions(hashes):
    hash_dict = defaultdict(list)
    collisions = []

    for i, h in enumerate(hashes):
        hash_dict[h].append(i)

    for hash_value, indices in hash_dict.items():
        if len(indices) > 1:
            collisions.append((hash_value, indices))
    
    return collisions

num_strings = 100 
string_length = 32  
random_strings = [generate_random_string(string_length) for _ in range(num_strings)]

results = {}

for algorithm in ['md5', 'sha1', 'sha256']:
    hashes, computation_time = measure_hash_time(random_strings, algorithm)
    collisions = detect_collisions(hashes)
    results[algorithm] = {
        'computation_time': computation_time,
        'collisions': collisions,
        'collision_count': len(collisions)
    }

for algorithm, data in results.items():
    print(f"\nAlgorithm: {algorithm.upper()}")
    print(f"Computation Time: {data['computation_time']:.6f} seconds")
    print(f"Number of Collisions: {data['collision_count']}")
    if data['collision_count'] > 0:
        print(f"Collisions: {data['collisions']}")
    else:
        print("No collisions detected.")
