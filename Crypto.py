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
from Utils import log_error, ErrorCode
import gc

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Crypto")
# Ensure logs propagate to root logger
logger.propagate = True

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
        """
        Initialize a SecureMessage.
        
        Args:
            ciphertext: The encrypted data
            nonce: The nonce used for encryption
            tag: The authentication tag
            version: Protocol version number
            salt: Salt used in key derivation
            
        Raises:
            TypeError: If inputs are not of the correct type
        """
        # Type validation
        if not isinstance(ciphertext, bytes):
            raise TypeError("ciphertext must be bytes")
        if not isinstance(nonce, bytes):
            raise TypeError("nonce must be bytes")
        if not isinstance(tag, bytes):
            raise TypeError("tag must be bytes")
        if not isinstance(version, int):
            raise TypeError("version must be int")
        if not isinstance(salt, bytes):
            raise TypeError("salt must be bytes")
            
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
        try:
            return cls(
                ciphertext=bytes.fromhex(data['ciphertext']),
                nonce=bytes.fromhex(data['nonce']),
                tag=bytes.fromhex(data['tag']),
                version=data['version'],
                salt=bytes.fromhex(data['salt'])
            )
        except ValueError as e:
            raise ValueError(f"Invalid hex string in data: {e}")

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
        """
        Verify nonce is unique and not expired.
        Returns True if nonce is valid (not used or expired), False otherwise.
        """
        with self._nonce_lock:
            current_time = time.time()
            self._cleanup_expired_nonces()
            
            # If nonce exists and hasn't expired, it's invalid
            if nonce in self._nonce_cache:
                timestamp = self._nonce_cache[nonce]
                if current_time - timestamp <= self._nonce_lifetime:
                    return False
                # If nonce has expired, remove it
                del self._nonce_cache[nonce]
            
            # Add the nonce with current timestamp
            self._nonce_cache[nonce] = current_time
            return True
            
    def _cleanup_expired_nonces(self):
        """Remove expired nonces from cache."""
        current_time = time.time()
        
        # Create a list of expired nonces first
        expired = []
        for nonce, timestamp in list(self._nonce_cache.items()):
            if current_time - timestamp > self._nonce_lifetime:
                expired.append(nonce)
        
        # Remove expired nonces
        for nonce in expired:
            del self._nonce_cache[nonce]
            
        # If cache is still too large, remove oldest entries
        if len(self._nonce_cache) > self._cache_size:
            # Convert to list before sorting to avoid dictionary modification during iteration
            sorted_nonces = sorted(list(self._nonce_cache.items()), key=lambda x: x[1])
            to_remove = len(self._nonce_cache) - self._cache_size
            for nonce, _ in sorted_nonces[:to_remove]:
                del self._nonce_cache[nonce]

class Crypto:
    def __init__(self):
        self._nonce_manager = NonceManager()
        self._key_cache = {}
        self._key_cache_lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 3600  # 1 hour

    def cleanup_key_cache(self):
        """Clean up expired keys from cache."""
        try:
            with self._key_cache_lock:
                current_time = time.time()
                expired_keys = []
                
                # Find expired keys
                for key_id, data in self._key_cache.items():
                    # Check if timestamp is an expiry time (future) or last access time (past)
                    if data['timestamp'] <= current_time:
                        expired_keys.append(key_id)
                
                # Securely clear expired keys
                for key_id in expired_keys:
                    key_data = self._key_cache[key_id]['key']
                    if isinstance(key_data, bytes):
                        # Securely overwrite the key data
                        self._key_cache[key_id]['key'] = b'\x00' * len(key_data)
                    # Remove the key from cache
                    del self._key_cache[key_id]
                    
                logger.info(f"Cleaned up {len(expired_keys)} expired keys")
                
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"Key cache cleanup failed: {e}")

    def __del__(self):
        """Ensure sensitive data is cleared from memory"""
        try:
            with self._key_cache_lock:
                for key_data in self._key_cache.values():
                    if isinstance(key_data.get('key'), bytes):
                        key_data['key'] = b'\x00' * len(key_data['key'])
                self._key_cache.clear()
        except Exception:
            pass

    @staticmethod
    def generate_key_pair(password: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Generate an EC key pair for key exchange.
        
        Args:
            password: Optional bytes to encrypt the private key. If provided, must not be empty.
            
        Returns:
            Tuple[bytes, bytes]: (public_key_pem, private_key_pem)
            
        Raises:
            ValueError: If password is provided but empty
            RuntimeError: For other key generation failures
        """
        # Check for empty password explicitly
        if password is not None and len(password) == 0:
            raise ValueError("Password cannot be empty")
            
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

        except ValueError as e:
            logger.error(f"Key pair generation failed: {str(e)}")
            raise  # Re-raise ValueError directly
        except Exception as e:
            logger.error(f"Key pair generation failed: {str(e)}")
            raise RuntimeError(f"Key pair generation failed: {str(e)}")
        
    @staticmethod
    def derive_session_key(peer_public_key: ec.EllipticCurvePublicKey,
                          private_key: ec.EllipticCurvePrivateKey,
                          context: bytes) -> bytes:
        """
        Derive a session key using ECDH and HKDF.
        
        Args:
            peer_public_key: Public key of the peer
            private_key: Private key for key agreement
            context: Context information for key derivation
            
        Returns:
            bytes: Derived session key
            
        Raises:
            ValueError: If keys are incompatible (e.g., different curves)
            RuntimeError: For other key derivation failures
        """
        shared_secret = None
        derived_key = None
        result = None
        
        try:
            # Generate salt for HKDF
            salt = secrets.token_bytes(CryptoConstants.SALT_SIZE)
            
            # Perform key agreement
            shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
            
            # Use HKDF with salt and context
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=CryptoConstants.AES_KEY_SIZE,
                salt=salt,
                info=context,
                backend=default_backend()
            ).derive(shared_secret)
            
            # Create a copy of the derived key
            result = bytes(derived_key)
            return result
            
        except ValueError as e:
            logger.error(f"Session key derivation failed: {str(e)}")
            raise  # Re-raise ValueError directly
        except Exception as e:
            logger.error(f"Session key derivation failed: {str(e)}")
            raise RuntimeError(f"Session key derivation failed: {str(e)}")
            
        finally:
            # Securely clear sensitive data from memory
            if shared_secret is not None:
                for i in range(len(shared_secret)):
                    shared_secret = shared_secret[:i] + b'\x00' + shared_secret[i+1:]
            if derived_key is not None:
                for i in range(len(derived_key)):
                    derived_key = derived_key[:i] + b'\x00' + derived_key[i+1:]
            # Force garbage collection
            gc.collect()

    @staticmethod
    def encrypt(data: bytes, key: bytes) -> SecureMessage:
        """Encrypt data using AES-GCM with authentication."""
        if not isinstance(data, bytes) or not isinstance(key, bytes):
            raise TypeError("Data and key must be bytes objects")
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")

        crypto = Crypto()  # Create instance for nonce management
        try:
            # Create copies of sensitive data to work with
            data_copy = bytes(data)
            key_copy = bytes(key)
            
            nonce = crypto._nonce_manager.generate_nonce()
            salt = secrets.token_bytes(CryptoConstants.SALT_SIZE)
            aesgcm = AESGCM(key_copy)
            
            # Encrypt in a way that minimizes data copies
            ciphertext_with_tag = aesgcm.encrypt(nonce, data_copy, None)
            
            # Split without creating additional copies
            tag = ciphertext_with_tag[-16:]
            ciphertext = ciphertext_with_tag[:-16]
            
            secure_msg = SecureMessage(
                ciphertext=ciphertext,
                nonce=nonce,
                tag=tag,
                version=CryptoConstants.VERSION,
                salt=salt
            )
            
            # Explicitly clear sensitive data
            key_copy = b'\x00' * len(key_copy)
            data_copy = b'\x00' * len(data_copy)
            ciphertext_with_tag = b'\x00' * len(ciphertext_with_tag)
            
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
        
        Args:
            key: The key used for MAC verification
            data: The data to verify
            mac: The MAC to verify against
            
        Returns:
            bool: True if MAC is valid, False if MAC doesn't match
            
        Raises:
            ValueError: If key or MAC have invalid size/format
            TypeError: If inputs are not bytes
        """
        # Input validation
        if not isinstance(key, bytes) or not isinstance(data, bytes) or not isinstance(mac, bytes):
            raise TypeError("All inputs must be bytes")
            
        if len(key) == 0:
            raise ValueError("Key cannot be empty")
            
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")
            
        if len(mac) == 0:
            raise ValueError("MAC cannot be empty")
            
        if len(mac) != CryptoConstants.MAC_SIZE:
            raise ValueError(f"MAC must be {CryptoConstants.MAC_SIZE} bytes long")
            
        try:
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(data)
            h.verify(mac)
            return True
        except InvalidTag:
            logger.error("MAC verification failed: Signature did not match digest.")
            return False
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
            ValueError: If the key length or nonce length is invalid
            InvalidTag: If the authentication tag is invalid
        """
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")
            
        if len(nonce) != CryptoConstants.NONCE_SIZE:
            raise ValueError(f"Nonce must be {CryptoConstants.NONCE_SIZE} bytes long")
        
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