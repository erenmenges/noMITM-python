from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256, Hash
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os

class Crypto:
    def generate_key_pair():

        # Generate ECDSA private key
        private_key = ec.generate_private_key(ec.SECP256R1())  # You can replace SECP256R1 with other curves like SECP384R1

        # Serialize private key to PEM format
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # Use a password here if encryption is needed
        )

        # Generate the corresponding public key
        public_key = private_key.public_key()

        # Serialize public key to PEM format
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return (public_pem, private_pem)
    
    def derive_session_key(peer_public_key, private_key):
        # Perform key agreement to derive the shared secret
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

        # Use HKDF to derive a symmetric session key from the shared secret
        derived_key = HKDF(
            algorithm=SHA256(),
            length=32,  # Length of the derived key in bytes
            salt=None,  # You can provide a salt for better security
            info=b"session_key",  # Contextual information
            backend=default_backend()
        ).derive(shared_secret)

        return derived_key

    def aes_encrypt(data, key):
        # Generate a random initialization vector (IV)
        iv = os.urandom(16)

        # Create a Cipher object with AES algorithm in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        # Pad the data to be a multiple of the block size (16 bytes for AES)
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        # Encrypt the data
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return iv, ciphertext
    
    def aes_decrypt(iv, ciphertext, key):
        # Create a Cipher object with AES algorithm in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

        # Decrypt the data
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding from the decrypted data
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data

    def hash(data):
        digest = Hash(SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()