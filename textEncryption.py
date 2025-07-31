from Crypto.Cipher import AES, DES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from base64 import b64encode
from cryptography.hazmat.primitives import serialization
import os

def aes_encrypt(plaintext):
    key = get_random_bytes(16)  # AES key (16 bytes = 128 bits)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return {
        'cipher': b64encode(ct_bytes).decode(),
        'key': b64encode(key).decode(),
        'iv': b64encode(cipher.iv).decode()
    }

def des_encrypt(plaintext):
    key = get_random_bytes(8)  # DES key (8 bytes)
    cipher = DES.new(key, DES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), DES.block_size))
    return {
        'cipher': b64encode(ct_bytes).decode(),
        'key': b64encode(key).decode(),
        'iv': b64encode(cipher.iv).decode()
    }

def rsa_encrypt(plaintext):
    key = RSA.generate(2048)
    public_key = key.publickey()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ct_bytes = cipher_rsa.encrypt(plaintext.encode())

    # Export public and private keys
    private_pem = key.export_key().decode()
    public_pem = public_key.export_key().decode()

    return {
        'cipher': b64encode(ct_bytes).decode(),
        'public_key': public_pem,
        'private_key': private_pem
    }

def main():
    print("Choose encryption algorithm:")
    print("1. AES\n2. DES\n3. RSA")
    choice = input("Enter choice (1/2/3): ")

    plaintext = input("Enter text to encrypt: ")

    if choice == '1':
        result = aes_encrypt(plaintext)
        print("\n AES Encryption:")
        print("Cipher Text:", result['cipher'])
        print("Key:", result['key'])
        print("IV:", result['iv'])

    elif choice == '2':
        result = des_encrypt(plaintext)
        print("\n DES Encryption:")
        print("Cipher Text:", result['cipher'])
        print("Key:", result['key'])
        print("IV:", result['iv'])

    elif choice == '3':
        result = rsa_encrypt(plaintext)
        print("\n RSA Encryption:")
        print("Cipher Text:", result['cipher'])
        print("Public Key:\n", result['public_key'])
        print("Private Key:\n", result['private_key'])

    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
