import os
import base64
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# -------------------- Step 1: Choose Action --------------------
def choose_action():
    while True:
        action = input("Do you want to (1) Encrypt or (2) Decrypt? Enter 1 or 2: ")
        if action in ("1", "2"):
            return action
        print("Invalid choice! Enter 1 or 2.")

# -------------------- Step 2: Choose Input Type --------------------
def choose_input_type():
    while True:
        choice = input("Do you want to handle (1) Text or (2) File/Image? Enter 1 or 2: ")
        if choice in ("1", "2"):
            return choice
        print("Invalid choice! Please enter 1 or 2.")

# -------------------- Step 3: Get Plaintext --------------------
def get_plaintext():
    print("Enter your plaintext (multi-line allowed). Press Enter twice to finish:")
    lines = []
    while True:
        line = input()
        if line.strip() == "":
            break
        lines.append(line)
    plaintext = "\n".join(lines)
    return plaintext.encode()  # Return bytes

# -------------------- Step 4: Get File/Image Bytes --------------------
def get_file_bytes():
    while True:
        file_path = input("Enter the path to the file/image: ")
        if os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                data = f.read()
            return data, file_path
        print("File not found! Please enter a valid path.")

# -------------------- Step 5: Get 32-byte Key --------------------
def get_32byte_key():
    while True:
        key_input = input("Enter a 32-byte encryption key (letters, numbers, symbols, spaces allowed): ")
        key_bytes = key_input.encode()
        if len(key_bytes) < 32:
            print("Error: Key too short! It must be exactly 32 bytes.")
        elif len(key_bytes) > 32:
            print("Error: Key too long! It must be exactly 32 bytes.")
        else:
            print("Key accepted.")
            return key_bytes

# -------------------- Step 6: Get 16-byte IV --------------------
def get_16byte_iv():
    while True:
        iv_input = input("Enter a 16-byte IV (press Enter to generate randomly): ")
        if iv_input == "":
            iv_bytes = os.urandom(16)
            print(f"Random IV generated: {base64.b64encode(iv_bytes).decode()}")
            return iv_bytes
        iv_bytes = iv_input.encode()
        if len(iv_bytes) < 16:
            print("Error: IV too short! It must be exactly 16 bytes.")
        elif len(iv_bytes) > 16:
            print("Error: IV too long! It must be exactly 16 bytes.")
        else:
            print("IV accepted.")
            return iv_bytes

# -------------------- Step 7: AES Encrypt --------------------
def aes_encrypt(data_bytes, key, iv):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return ciphertext

# -------------------- Step 8: AES Decrypt --------------------
def aes_decrypt(ciphertext_bytes, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded = decryptor.update(ciphertext_bytes) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(decrypted_padded) + unpadder.finalize()
    return decrypted

# -------------------- Fainal Step 9 --------------------
action = choose_action()
choice = choose_input_type()

key = get_32byte_key()
iv = get_16byte_iv()

if action == "1":  # ENCRYPT
    if choice == "1":  # Text
        data_bytes = get_plaintext()
        ciphertext = aes_encrypt(data_bytes, key, iv)
        print("\n--- Encryption Result ---")
        print("Ciphertext (Base64):", base64.b64encode(ciphertext).decode())
    else:  # File/Image
        data_bytes, original_name = get_file_bytes()
        ciphertext = aes_encrypt(data_bytes, key, iv)
        folder = os.path.dirname(original_name)
        encrypted_file_path = os.path.join(folder, "encrypted_" + os.path.basename(original_name))
        with open(encrypted_file_path, "wb") as f:
            f.write(ciphertext)
        print(f"\nEncrypted file saved as: {encrypted_file_path}")

else:  # DECRYPT
    if choice == "1":  # Text
        encrypted_b64 = input("Enter the Base64 encrypted text: ")
        encrypted_bytes = base64.b64decode(encrypted_b64)
        decrypted = aes_decrypt(encrypted_bytes, key, iv)
        print("\n--- Decryption Result ---")
        try:
            print("Decrypted Text:", decrypted.decode())
        except UnicodeDecodeError:
            print("Error: Decrypted bytes could not be decoded as UTF-8. Maybe wrong key/IV or not text.")
    else:  # File/Image
        encrypted_bytes, original_name = get_file_bytes()
        decrypted = aes_decrypt(encrypted_bytes, key, iv)
        folder = os.path.dirname(original_name)
        decrypted_file_path = os.path.join(folder, "decrypted_" + os.path.basename(original_name))
        with open(decrypted_file_path, "wb") as f:
            f.write(decrypted)
        print(f"\nDecrypted file saved as: {decrypted_file_path}")
