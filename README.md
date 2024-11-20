
This project builds upon the previous version of the file encryption and decryption
tool by introducing user-specific keys secured with a username and password.
This improvement ensures that only authorized users can encrypt or decrypt files,
adding a personalized layer of security. The encryption and decryption processes are
implemented using the cryptography library, specifically the Fernet module, which ensures
robust data security.

The first script, set_key.py, generates and saves encryption keys for individual users. 
A user starts by entering their username and a secure password, which is used to derive a 
key compatible with the Fernet module. This derived key encrypts the unique encryption key
generated for the user. The encrypted key is then stored in a secure location within a keys 

directory. This ensures that only the user with the correct password can retrieve and use their 
encryption key. If a key for the username already exists, the script prompts the user before
overwriting it. The key creation process relies on the cryptography, hashlib, and base64 libraries 
to ensure the integrity and compatibility of the encryption process. Secure password input is handled
by the getpass library, and the os library is used to manage the file system for storing keys.

The second script, file_encrypt_decrypt_gui.py, provides a graphical user interface where users
can log in with their username and password to encrypt or decrypt files. Upon successful login, 
the script loads the user's encryption key from the secure keys directory, decrypting it using the
password provided at login. The user can then select files to encrypt or decrypt. When a file is encrypted,
metadata is generated to track which user performed the encryption, ensuring traceability. This metadata 
is stored alongside the encrypted file. During decryption, the tool checks this metadata to verify whether
the current user encrypted the file and warns the user if a different username is associated with the file. 
The decryption process still proceeds if the user has the correct key. The tkinter library is used to provide a user-friendly graphical interface, while the json library manages metadata storage. File operations are handled by the os library, and encryption and decryption rely on the cryptography library.

This enhanced system is designed to provide secure, user-specific encryption and decryption capabilities.
By combining a username and password mechanism with metadata tracking, the tool ensures file security 
and accountability. Each user has their own encryption key, and files are accessible only to those with 
the correct credentials. The improvement over the previous version lies in the ability to handle multiple
users securely, making this tool suitable for scenarios where data confidentiality is critical.
The reliance on industry-standard libraries like cryptography guarantees the robustness of the
encryption and decryption processes, while the use of a graphical interface makes the tool accessible
even to non-technical users.
