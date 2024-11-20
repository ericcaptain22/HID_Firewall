# File: scripts/encryption.py

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

# AES encryption requires a key of fixed length
# This should be kept secure in a real-world scenario
key = b'Sixteen byte key'  # 16 bytes key for AES-128

def encrypt_data(data):
    """
    Encrypts the given data using AES encryption.
    
    Parameters:
    data (str): The plaintext data to encrypt.
    
    Returns:
    str: The base64 encoded encrypted data.
    """
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    encrypted_data = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
    return base64.b64encode(iv + encrypted_data).decode('utf-8')

def decrypt_data(encrypted_data):
    """
    Decrypts the given encrypted data using AES encryption.
    
    Parameters:
    encrypted_data (str): The base64 encoded encrypted data to decrypt.
    
    Returns:
    str: The decrypted plaintext data.
    """
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[AES.block_size:]), AES.block_size)
    return decrypted_data.decode('utf-8')

if __name__ == "__main__":
    # Example usage
    plaintext = "Hello World"
    encrypted = encrypt_data(plaintext)
    print(f'Encrypted: {encrypted}')
    decrypted = decrypt_data(encrypted)
    print(f'Decrypted: {decrypted}')
