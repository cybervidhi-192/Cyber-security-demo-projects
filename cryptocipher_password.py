from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os

# -----------------------------
# CREATE KEY FROM PASSWORD
# -----------------------------
def generate_key_from_password(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# -----------------------------
# ENCRYPT MESSAGE
# -----------------------------
def encrypt_message(password, message):
    salt = os.urandom(16)  # random salt
    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)

    encrypted = cipher.encrypt(message.encode())

    # combine salt + encrypted text
    final_data = base64.urlsafe_b64encode(salt + encrypted)
    print("\n🔒 Encrypted Message:\n")
    print(final_data.decode())

# -----------------------------
# DECRYPT MESSAGE
# -----------------------------
def decrypt_message(password, encrypted_data):
    decoded_data = base64.urlsafe_b64decode(encrypted_data.encode())

    salt = decoded_data[:16]
    encrypted_message = decoded_data[16:]

    key = generate_key_from_password(password, salt)
    cipher = Fernet(key)

    decrypted = cipher.decrypt(encrypted_message)
    print("\n🔓 Decrypted Message:\n")
    print(decrypted.decode())

# -----------------------------
# CLI MENU
# -----------------------------
def main():
    print("\n===== Password CryptoCipher =====")
    print("1. Encrypt Message")
    print("2. Decrypt Message")
    choice = input("Enter choice: ")

    password = input("Enter password: ")

    if choice == "1":
        msg = input("Enter message: ")
        encrypt_message(password, msg)

    elif choice == "2":
        enc = input("Paste encrypted message: ")
        decrypt_message(password, enc)

    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()