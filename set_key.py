from cryptography.fernet import Fernet
import hashlib
import base64
import os
from getpass import getpass

def generate_user_key(username):
    os.makedirs("keys", exist_ok=True)
    user_key_path = f"keys/{username}.key"

    if os.path.exists(user_key_path):
        print("Key already exists for the user. Overwrite? (y/n)")
        if input().lower() != "y":
            return

    # Ask for a password to protect the key
    password = getpass("Enter a password to protect your key: ")

    # Derive a Fernet-compatible key from the password
    hashed_password = hashlib.sha256(password.encode()).digest()
    derived_key = base64.urlsafe_b64encode(hashed_password[:32])  # Use the first 32 bytes
    
    key = Fernet.generate_key()
    encrypted_key = Fernet(derived_key).encrypt(key)

    with open(user_key_path, "wb") as key_file:
        key_file.write(encrypted_key)
    print(f"Key for user '{username}' successfully saved.")

def load_user_key(username):
    user_key_path = f"keys/{username}.key"
    
    if not os.path.exists(user_key_path):
        raise FileNotFoundError(f"Key for user '{username}' not found.")
    
    password = getpass("Enter the password to decrypt your key: ")
    hashed_password = hashlib.sha256(password.encode()).digest()
    derived_key = base64.urlsafe_b64encode(hashed_password[:32])  # Use the first 32 bytes

    with open(user_key_path, "rb") as key_file:
        encrypted_key = key_file.read()

    try:
        return Fernet(derived_key).decrypt(encrypted_key)
    except Exception as e:
        raise ValueError("Incorrect password or corrupted key.")

if __name__ == "__main__":
    username = input("Enter your username: ")
    generate_user_key(username)
