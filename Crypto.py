from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, aead
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import os
import secrets
import logging
from typing import Optional, Tuple, Dict, Any
import threading
import time

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

    def to_dict(self) -> Dict[str, Any]:
        return {
            'ciphertext': self.ciphertext.hex(),
            'nonce': self.nonce.hex(),
            'tag': self.tag.hex(),
            'version': self.version,
            'salt': self.salt.hex()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecureMessage':
        return cls(
            ciphertext=bytes.fromhex(data['ciphertext']),
            nonce=bytes.fromhex(data['nonce']),
            tag=bytes.fromhex(data['tag']),
            version=data['version'],
            salt=bytes.fromhex(data['salt'])
        )

class NonceManager:
    def __init__(self, cache_size=10000, nonce_lifetime=300):  # 5 minutes lifetime
        self._nonce_cache = {}  # Dictionary to store nonce with timestamp
        self._nonce_lock = threading.Lock()
        self._cache_size = cache_size
        self._nonce_lifetime = nonce_lifetime
        
    def generate_nonce(self) -> bytes:
        """Generate a unique nonce with timestamp."""
        with self._nonce_lock:
            while True:
                nonce = secrets.token_bytes(CryptoConstants.NONCE_SIZE)
                current_time = time.time()
                
                # Clean expired nonces
                self._cleanup_expired_nonces()
                
                if nonce not in self._nonce_cache:
                    self._nonce_cache[nonce] = current_time
                    return nonce
                    
    def verify_nonce(self, nonce: bytes) -> bool:
        """Verify nonce is unique and not expired."""
        with self._nonce_lock:
            if nonce in self._nonce_cache:
                return False
            current_time = time.time()
            self._nonce_cache[nonce] = current_time
            self._cleanup_expired_nonces()
            return True
            
    def _cleanup_expired_nonces(self):
        """Remove expired nonces from cache."""
        current_time = time.time()
        expired = [
            nonce for nonce, timestamp in self._nonce_cache.items()
            if current_time - timestamp > self._nonce_lifetime
        ]
        for nonce in expired:
            del self._nonce_cache[nonce]

class Crypto:
    def __init__(self):
        self._nonce_manager = NonceManager()
        self._key_cache = {}
        self._key_cache_lock = threading.Lock()

    def __del__(self):
        """Ensure sensitive data is cleared from memory"""
        try:
            with self._key_cache_lock:
                for key in self._key_cache:
                    # Overwrite with zeros before deletion
                    self._key_cache[key] = b'\x00' * len(self._key_cache[key])
                self._key_cache.clear()
        except Exception:
            pass

    def _generate_unique_nonce(self) -> bytes:
        """Generate a unique nonce that hasn't been used recently."""
        with self._nonce_lock:
            while True:
                nonce = secrets.token_bytes(CryptoConstants.NONCE_SIZE)
                if nonce not in self._nonce_cache:
                    self._nonce_cache.add(nonce)
                    # Cleanup old nonces if cache gets too large
                    if len(self._nonce_cache) > self._nonce_cleanup_threshold:
                        self._nonce_cache.clear()
                    return nonce

    @staticmethod
    def generate_key_pair(password: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Generate an EC key pair for key exchange.
        Returns: (public_key_pem, private_key_pem)
        """
        try:
            private_key = ec.generate_private_key(
                CryptoConstants.CURVE,
                backend=default_backend()
            )

            # Use password for private key encryption if provided
            encryption_algorithm = (
                serialization.NoEncryption()
                if password is None
                else serialization.BestAvailableEncryption(password)
            )

            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            )

            public_key = private_key.public_key()
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            logger.info("Generated new key pair")
            return public_pem, private_pem

        except Exception as e:
            logger.error(f"Key pair generation failed: {str(e)}")
            raise RuntimeError(f"Key pair generation failed: {str(e)}")
        
    @staticmethod
    def derive_session_key(peer_public_key: ec.EllipticCurvePublicKey,
                          private_key: ec.EllipticCurvePrivateKey,
                          context: bytes) -> bytes:
        """Derive a session key using ECDH and HKDF."""
        try:
            # Generate salt for HKDF
            salt = secrets.token_bytes(CryptoConstants.SALT_SIZE)
            
            # Perform key agreement
            shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
            
            # Use HKDF with salt and context
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=CryptoConstants.AES_KEY_SIZE,
                salt=salt,  # Use generated salt instead of None
                info=context,
                backend=default_backend()
            ).derive(shared_secret)
            
            # Securely clear shared secret from memory
            shared_secret = b'\x00' * len(shared_secret)
            
            return derived_key
        except Exception as e:
            logger.error(f"Session key derivation failed: {str(e)}")
            raise RuntimeError(f"Session key derivation failed: {str(e)}")

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> SecureMessage:
        """Encrypt data using AES-GCM with authentication."""
        if not isinstance(data, bytes) or not isinstance(key, bytes):
            raise TypeError("Data and key must be bytes objects")
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")

        crypto = Crypto()  # Create instance for nonce management
        try:
            nonce = crypto._generate_unique_nonce()
            
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
        except Exception as e:
            logger.error(f"MAC verification failed: {e}")
            return False

    @staticmethod
    def aes_encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-GCM and return (nonce, ciphertext, tag).
        """
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")
        
        try:
            nonce = secrets.token_bytes(CryptoConstants.NONCE_SIZE)
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, data, None)
            tag = ciphertext[-16:]
            ciphertext = ciphertext[:-16]
            return nonce, ciphertext, tag
        except Exception as e:
            logger.error(f"AES encryption failed: {e}")
            raise RuntimeError(f"AES encryption failed: {e}")

    @staticmethod
    def aes_decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
        """
        Decrypt data using AES-GCM with explicit tag validation.
        
        Args:
            ciphertext: The encrypted data
            key: The encryption key
            nonce: The nonce used for encryption
            tag: The authentication tag
            
        Returns:
            The decrypted data
            
        Raises:
            InvalidTag: If the authentication tag is invalid
            ValueError: If the key length is invalid
        """
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")
        
        try:
            # Create AESGCM instance
            aesgcm = AESGCM(key)
            
            # Explicitly verify the tag by attempting decryption
            # If tag is invalid, this will raise InvalidTag
            plaintext = aesgcm.decrypt(nonce, ciphertext + tag, None)
            
            return plaintext
        except InvalidTag as e:
            logger.error("Authentication tag verification failed")
            raise InvalidTag("Message authentication failed - possible tampering detected")
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise RuntimeError(f"Decryption failed: {e}")