# import base64 library for encoding/decoding data
import base64
# import os library for accessing system-related functions
import os
# import default_backend and hashes from cryptography library
# these libraries will be used for key derivation function (KDF)
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
# import PBKDF2HMAC for deriving key from password using KDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
# import Fernet from cryptography library for encryption/decryption
from cryptography.fernet import Fernet

# Use a fixed salt every time for key derivation
salt = b'\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef\xde\xad\xbe\xef'

# Function for encrypting a message with a password
def encrypt_message(message, password):
    # Key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256, # algorithm to use for KDF
        iterations=100000, # number of iterations
        salt=salt, # salt to use in KDF
        length=32, # length of the derived key
        backend=default_backend()
    )
    # derive key from password using the KDF
    key = base64.urlsafe_b64encode(kdf.derive(password))
    # Create Fernet instance to encrypt message
    f = Fernet(key)
    # encrypt the message
    encrypted_message = f.encrypt(message)
    # return encrypted message
    return encrypted_message

# Function for decrypting a message with a password
def decrypt_message(encrypted_message, password):
    # Key derivation function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256, # algorithm to use for KDF
        iterations=100000, # number of iterations
        salt=salt, # salt to use in KDF
        length=32, # length of the derived key
        backend=default_backend()
    )
    # derive key from password using the KDF
    key = base64.urlsafe_b64encode(kdf.derive(password))
    # Create Fernet instance to decrypt message
    f = Fernet(key)
    # decrypt the message
    decrypted_message = f.decrypt(encrypted_message)
    # return decrypted message
    return decrypted_message
    
# run the code only if the script is executed as main
if __name__ == '__main__':
    # password for encryption, encoded as bytes
    password = "This is a password to encrypt message".encode()
    # message to be encrypted, encoded as bytes
    message = "This is a secret message".encode()
    # encrypt the message
    encrypted_message = encrypt_message(message, password)
    # print the encrypted message
    print("Encrypted message:", encrypted_message)
    # decrypt the encrypted message
    decrypted_message = decrypt_message(encrypted_message, password)
    # print the decrypted message as string
    print("Decrypted message:", decrypted_message.decode())
