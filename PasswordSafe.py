import hashlib
from cryptography.fernet import Fernet

def hash_password(password):
    # Hashes the given password using SHA-256 algorithm
    return hashlib.sha256(password.encode()).hexdigest()

def encrypt_password(password, key):
    # Encrypts the password using Fernet encryption
    f = Fernet(key)
    return f.encrypt(password.encode())

def decrypt_password(encrypted_password, key):
    # Decrypts the password using Fernet decryption
    f = Fernet(key)
    return f.decrypt(encrypted_password).decode()

def store_password(service, username, password):
    # Generates a key based on the service name and username
    key = hashlib.sha256((service + username).encode()).digest()

    # Encrypts the password using the key
    encrypted_password = encrypt_password(password, key)

    # Writes the encrypted password to a file
    with open('passwords.txt', 'a') as f:
        f.write(f'{service} {username} {encrypted_password.hex()}\n')

def retrieve_password(service, username):
    # Generates a key based on the service name and username
    key = hashlib.sha256((service + username).encode()).digest()

    # Reads the stored passwords from the file
    with open('passwords.txt', 'r') as f:
        for line in f:
            fields = line.strip().split()
            if fields[0] == service and fields[1] == username:
                # Decrypts the password using the key
                encrypted_password = bytes.fromhex(fields[2])
                return decrypt_password(encrypted_password, key)

    # If no matching password is found, returns None
    return None
