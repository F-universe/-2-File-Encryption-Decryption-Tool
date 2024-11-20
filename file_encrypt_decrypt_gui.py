import os
from tkinter import Tk, filedialog, Button, Label
from cryptography.fernet import Fernet
import json

def load_key(username):
    from set_key import load_user_key
    return load_user_key(username)

def encrypt_file(file_path, username):
    key = load_key(username)
    fernet = Fernet(key)

    with open(file_path, "rb") as file:
        original_data = file.read()

    encrypted_data = fernet.encrypt(original_data)

    # Save the encrypted file
    encrypted_file_path = file_path + ".encrypted"
    with open(encrypted_file_path, "wb") as encrypted_file:
        encrypted_file.write(encrypted_data)

    # Create metadata to track who encrypted the file
    metadata = {"encrypted_by": username}
    metadata_file_path = file_path + ".metadata"
    with open(metadata_file_path, "w") as metadata_file:
        json.dump(metadata, metadata_file)

    print(f"File '{file_path}' successfully encrypted as '{encrypted_file_path}'.")

def decrypt_file(file_path, username):
    key = load_key(username)
    fernet = Fernet(key)

    metadata_file_path = file_path.replace(".encrypted", ".metadata")

    try:
        # Check who encrypted the file
        if os.path.exists(metadata_file_path):
            with open(metadata_file_path, "r") as metadata_file:
                metadata = json.load(metadata_file)
                encrypted_by = metadata.get("encrypted_by", "unknown")

                if encrypted_by != username:
                    print(f"Warning: This file was encrypted by another user: '{encrypted_by}'.")

        # Decrypt the file
        with open(file_path, "rb") as encrypted_file:
            encrypted_data = encrypted_file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        # Save the decrypted file, overwrite if it exists for the same user
        user_decrypted_path = f"{file_path.replace('.encrypted', '')}_{username}_decrypted.txt"
        with open(user_decrypted_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File '{file_path}' successfully decrypted as '{user_decrypted_path}'.")
    except Exception as e:
        print(f"Error during decryption: {e}")

def select_file_encrypt(username):
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if file_path:
        encrypt_file(file_path, username)

def select_file_decrypt(username):
    file_path = filedialog.askopenfilename(title="Select a file to decrypt")
    if file_path:
        decrypt_file(file_path, username)

def create_gui():
    root = Tk()
    root.title("File Encryption & Decryption Tool")
    root.geometry("400x300")

    username = input("Enter your username: ")

    Label(root, text="Choose an option:", font=("Helvetica", 14)).pack(pady=10)
    Button(root, text="Encrypt a File", command=lambda: select_file_encrypt(username), width=30).pack(pady=10)
    Button(root, text="Decrypt a File", command=lambda: select_file_decrypt(username), width=30).pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    create_gui()
