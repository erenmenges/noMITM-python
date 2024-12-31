from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import os
import secrets
import logging
from typing import Optional, Tuple, Dict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CryptoConstants:
    AES_KEY_SIZE = 32  # 256 bits
    AES_BLOCK_SIZE = 16  # 128 bits
    NONCE_SIZE = 12  # For GCM mode
    SALT_SIZE = 32
    MAC_SIZE = 32
    VERSION = 1  # Protocol version
    CURVE = ec.SECP256R1()
    
class SecureMessage:
    def __init__(self, ciphertext: bytes, nonce: bytes, tag: bytes, 
                 version: int, salt: bytes):
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag
        self.version = version
        self.salt = salt

    def to_dict(self) -> Dict[str, bytes]:
        return {
            'ciphertext': self.ciphertext,
            'nonce': self.nonce,
            'tag': self.tag,
            'version': self.version.to_bytes(4, 'big'),
            'salt': self.salt
        }

    @classmethod
    def from_dict(cls, data: Dict[str, bytes]) -> 'SecureMessage':
        return cls(
            ciphertext=data['ciphertext'],
            nonce=data['nonce'],
            tag=data['tag'],
            version=int.from_bytes(data['version'], 'big'),
            salt=data['salt']
        )

class Crypto:
    def __init__(self):
        # Verify that we have a secure random number generator
        if not os.urandom(1):
            raise RuntimeError("Secure random number generator is not available")

    @staticmethod
    def generate_key_pair() -> Tuple[bytes, bytes]:
        """
        Generate an EC key pair for key exchange.
        Returns: (public_key_pem, private_key_pem)
        """
        try:
            private_key = ec.generate_private_key(
                CryptoConstants.CURVE,
                backend=default_backend()
            )

            # Use strong encryption for private key storage
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    secrets.token_bytes(32)
                )
            )

            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            logger.info("Generated new key pair")
            return (public_pem, private_pem)
        except Exception as e:
            logger.error(f"Key pair generation failed: {str(e)}")
            raise RuntimeError(f"Key pair generation failed: {str(e)}")
        
    @staticmethod
    def derive_session_key(peer_public_key: ec.EllipticCurvePublicKey,
                          private_key: ec.EllipticCurvePrivateKey,
                          context: bytes) -> bytes:
        """
        Derive a session key using ECDH and HKDF.
        """
        try:

            # Perform key agreement
            shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)

            # Use HKDF with salt and context
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=CryptoConstants.AES_KEY_SIZE,
                salt=None,
                info=context,
                backend=default_backend()
            ).derive(shared_secret)

            logger.info("Derived new session key")
            return derived_key
        except Exception as e:
            logger.error(f"Session key derivation failed: {str(e)}")
            raise RuntimeError(f"Session key derivation failed: {str(e)}")

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> SecureMessage:
        """
        Encrypt data using AES-GCM with authentication.
        """
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")

        try:
            # Generate a random nonce
            nonce = secrets.token_bytes(CryptoConstants.NONCE_SIZE)
            
            # Generate a random salt for key derivation
            salt = secrets.token_bytes(CryptoConstants.SALT_SIZE)

            # Create an AESGCM instance
            aesgcm = AESGCM(key)

            # Encrypt and authenticate the data
            ciphertext = aesgcm.encrypt(
                nonce,
                data,
                None  # Additional authenticated data (optional)
            )

            # Split the ciphertext and authentication tag
            tag = ciphertext[-16:]  # GCM tag is 16 bytes
            ciphertext = ciphertext[:-16]

            secure_msg = SecureMessage(
                ciphertext=ciphertext,
                nonce=nonce,
                tag=tag,
                version=CryptoConstants.VERSION,
                salt=salt
            )

            logger.info("Data encrypted successfully")
            return secure_msg

        except Exception as e:
            logger.error(f"Encryption failed: {str(e)}")
            raise RuntimeError(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt(secure_msg: SecureMessage, key: bytes) -> bytes:
        """
        Decrypt data using AES-GCM with authentication.
        """
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")

        if secure_msg.version != CryptoConstants.VERSION:
            raise ValueError("Unsupported protocol version")

        try:
            # Create an AESGCM instance
            aesgcm = AESGCM(key)

            # Combine ciphertext and tag
            ciphertext_with_tag = secure_msg.ciphertext + secure_msg.tag

            # Decrypt and verify the data
            plaintext = aesgcm.decrypt(
                secure_msg.nonce,
                ciphertext_with_tag,
                None  # Additional authenticated data (optional)
            )

            logger.info("Data decrypted successfully")
            return plaintext

        except Exception as e:
            logger.error(f"Decryption failed: {str(e)}")
            raise RuntimeError(f"Decryption failed: {str(e)}")

    @staticmethod
    def hash(data: bytes) -> bytes:
        """
        Create a secure hash of data using SHA-256.
        """
        try:
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(data)
            return digest.finalize()
        except Exception as e:
            logger.error(f"Hashing failed: {str(e)}")
            raise RuntimeError(f"Hashing failed: {str(e)}")

    @staticmethod
    def create_mac(key: bytes, data: bytes) -> bytes:
        """
        Create a MAC (Message Authentication Code) using HMAC-SHA256.
        """
        try:
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(data)
            return h.finalize()
        except Exception as e:
            logger.error(f"MAC creation failed: {str(e)}")
            raise RuntimeError(f"MAC creation failed: {str(e)}")

    @staticmethod
    def verify_mac(key: bytes, data: bytes, mac: bytes) -> bool:
        """
        Verify a MAC (Message Authentication Code).
        """
        try:
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(data)
            h.verify(mac)
            return True
        except Exception:
            return False