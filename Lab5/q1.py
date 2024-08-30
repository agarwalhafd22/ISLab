def custom_hash(input_string):
    hash_value = 5381
    
    for char in input_string:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)  
        
        hash_value &= 0xFFFFFFFF 
    return hash_value


print(custom_hash("Hello, World!"))  
print(custom_hash("Hello, World"))  
print(custom_hash("Hello World"))  