# File: scripts/encryption.py

from cryptography.fernet import Fernet

# Generate and securely store the encryption key in a real-world scenario
key = Fernet.generate_key()  # This should be stored securely
cipher = Fernet(key)

def encrypt_message(message):
    """
    Encrypts the given message using Fernet encryption.

    Parameters:
    message (str): The plaintext message to encrypt.

    Returns:
    str: The encrypted message (in base64 format).
    """
    try:
        encrypted_message = cipher.encrypt(message.encode())
        return encrypted_message.decode()
    except Exception as e:
        print(f"Error encrypting message: {e}")
        return None

def decrypt_message(encrypted_message):
    """
    Decrypts the given encrypted message using Fernet encryption.

    Parameters:
    encrypted_message (str): The encrypted message (in base64 format).

    Returns:
    str: The decrypted plaintext message.
    """
    try:
        decrypted_message = cipher.decrypt(encrypted_message.encode())
        return decrypted_message.decode()
    except Exception as e:
        print(f"Error decrypting message: {e}")
        return None

if __name__ == "__main__":
    # Example usage
    plaintext = "Sensitive log data"
    encrypted = encrypt_message(plaintext)
    print(f'Encrypted: {encrypted}')
    
    decrypted = decrypt_message(encrypted)
    print(f'Decrypted: {decrypted}')
