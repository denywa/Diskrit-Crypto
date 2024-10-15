import hashlib

def generate_keys(secret_key):
    hashed_key = hashlib.md5(secret_key.encode()).digest()
    
    B1 = hashed_key[0]
    B2 = hashed_key[1]
    B3 = hashed_key[2]
    B4 = hashed_key[3]
    
    return B1, B2, B3, B4

def encrypt(plaintext, secret_key):
    B1, B2, B3, B4 = generate_keys(secret_key)
    
    A = int.from_bytes(plaintext.encode(), 'big')
    C = (((A ^ B1) ^ B2) ^ B3) ^ B4
    
    return C

def decrypt(ciphertext, secret_key):
    B1, B2, B3, B4 = generate_keys(secret_key)
    
    A = (((ciphertext ^ B4) ^ B3) ^ B2) ^ B1
    plaintext = A.to_bytes((A.bit_length() + 7) // 8, 'big').decode()
    
    return plaintext


secret_key = "kunci"
plaintext = "Hello"

ciphertext = encrypt(plaintext, secret_key)
print(f"Ciphertext: {ciphertext}")

decrypted_text = decrypt(ciphertext, secret_key)
print(f"Decrypted Text: {decrypted_text}")
