from cryptography.fernet import Fernet
import os

# Function to generate and save encryption key
def generate_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)
    print("[+] Encryption key saved as secret.key")
    return key

# Function to load the key
def load_key():
    return open("secret.key", "rb").read()

# Function to encrypt the image file
def encrypt_image(image_path, key):
    with open(image_path, "rb") as file:
        image_data = file.read()

    fernet = Fernet(key)
    encrypted = fernet.encrypt(image_data)

    with open(image_path + ".enc", "wb") as file:
        file.write(encrypted)

    print(f"[+] Encrypted image saved as {image_path}.enc")

# Function to decrypt the image file
def decrypt_image(encrypted_path, key):
    with open(encrypted_path, "rb") as file:
        encrypted_data = file.read()

    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data)

    original_path = encrypted_path.replace(".enc", "_decrypted" + os.path.splitext(encrypted_path)[1])
    with open(original_path, "wb") as file:
        file.write(decrypted)

    print(f"[+] Decrypted image saved as {original_path}")

# Simple CLI
def main():
    print("1. Generate Key\n2. Encrypt Image\n3. Decrypt Image")
    choice = input("Select option: ")

    if choice == '1':
        generate_key()
    elif choice == '2':
        key = load_key()
        path = input("Enter image path to encrypt: ")
        encrypt_image(path, key)
    elif choice == '3':
        key = load_key()
        path = input("Enter encrypted image file path: ")
        decrypt_image(path, key)
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
