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
from Utils import log_error, ErrorCode, log_event
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
    CURVE = ec.SECP256R1()  # Standard NIST P-256 curve
    KEY_EXCHANGE_TIMEOUT = 30  # seconds
    
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
        log_event("Crypto", "[CRYPTO] Initializing Crypto instance")
        self._nonce_manager = NonceManager()
        self._key_cache = {}
        self._key_cache_lock = threading.Lock()
        self._last_cleanup = time.time()
        self._cleanup_interval = 3600  # 1 hour
        log_event("Crypto", "[CRYPTO] Crypto instance initialized successfully")

    def cleanup_key_cache(self):
        """Clean up expired keys from cache."""
        try:
            log_event("Crypto", "[CRYPTO] Starting key cache cleanup")
            with self._key_cache_lock:
                current_time = time.time()
                expired_keys = []
                
                # Find expired keys
                for key_id, data in self._key_cache.items():
                    log_event("Crypto", f"[CRYPTO] Checking expiry for key: {key_id}")
                    if data['timestamp'] <= current_time:
                        expired_keys.append(key_id)
                
                log_event("Crypto", f"[CRYPTO] Found {len(expired_keys)} expired keys to clean up")
                
                # Securely clear expired keys
                for key_id in expired_keys:
                    log_event("Crypto", f"[CRYPTO] Securely clearing key: {key_id}")
                    key_data = self._key_cache[key_id]['key']
                    if isinstance(key_data, bytes):
                        self._key_cache[key_id]['key'] = b'\x00' * len(key_data)
                    del self._key_cache[key_id]
                    
                log_event("Crypto", f"[CRYPTO] Successfully cleaned up {len(expired_keys)} expired keys")
                
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] Key cache cleanup failed: {e}")

    def __del__(self):
        """Ensure sensitive data is cleared from memory"""
        try:
            log_event("Crypto", "[CRYPTO] Starting secure cleanup in destructor")
            with self._key_cache_lock:
                count = 0
                for key_data in self._key_cache.values():
                    if isinstance(key_data.get('key'), bytes):
                        key_data['key'] = b'\x00' * len(key_data['key'])
                        count += 1
                self._key_cache.clear()
                log_event("Crypto", f"[CRYPTO] Securely cleared {count} keys from cache")
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] Error during secure cleanup: {e}")

    @staticmethod
    def generate_key_pair(password: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Generate an EC key pair for key exchange.
        
        Args:
            password: Optional bytes to encrypt the private key
            
        Returns:
            Tuple[bytes, bytes]: (public_key_pem, private_key_pem)
        """
        try:
            log_event("Security", "[CRYPTO] Generating EC key pair")
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
            
            log_event("Security", "[CRYPTO] Key pair generated successfully")
            return public_pem, private_pem
            
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] Key pair generation failed: {str(e)}")
            raise

    @staticmethod
    def derive_shared_key(private_key: ec.EllipticCurvePrivateKey, 
                         peer_public_key: ec.EllipticCurvePublicKey) -> bytes:
        """
        Derive a shared key using ECDH.
        
        Args:
            private_key: Local private key
            peer_public_key: Peer's public key
            
        Returns:
            bytes: Derived shared key
        """
        try:
            shared_key = private_key.exchange(
                ec.ECDH(),
                peer_public_key
            )
            
            # Derive final key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=None,
                info=b'session key',
                backend=default_backend()
            ).derive(shared_key)
            
            return derived_key
            
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] Key derivation failed: {str(e)}")
            raise

    @staticmethod
    def derive_session_key(peer_public_key, private_key, context: bytes) -> bytes:
        """
        Derive a shared session key using ECDH and HKDF.
        
        Args:
            peer_public_key: The peer's public key
            private_key: Our private key
            context: Context info for the key derivation
            
        Returns:
            bytes: The derived session key
        """
        try:
            log_event("Crypto", "[CRYPTO] Starting session key derivation")
            
            # Perform ECDH key agreement
            log_event("Crypto", "[CRYPTO] Performing ECDH key agreement")
            shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
            
            # Derive final key using HKDF
            log_event("Crypto", "[CRYPTO] Performing HKDF key derivation")
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=CryptoConstants.AES_KEY_SIZE,
                salt=None,  # Remove salt
                info=context,
                backend=default_backend()
            )
            derived_key = hkdf.derive(shared_key)
            
            log_event("Crypto", "[CRYPTO] Session key derived successfully")
            return derived_key
            
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"Session key derivation failed: {e}")
            raise

    @staticmethod
    def encrypt(data: bytes, key: bytes, associated_data: bytes = None) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Encrypt data using AES-GCM with authentication.
        
        Args:
            data: The plaintext to encrypt
            key: The encryption key
            associated_data: Optional authenticated associated data
            
        Returns:
            Tuple[bytes, bytes, bytes, bytes]: (ciphertext, nonce, tag, salt)
        """
        log_event("Crypto", "[CRYPTO] Starting encryption process")
        
        if not isinstance(data, bytes) or not isinstance(key, bytes):
            log_error(ErrorCode.CRYPTO_ERROR, "[CRYPTO] Invalid input types for encryption")
            raise TypeError("Data and key must be bytes objects")
            
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            log_error(ErrorCode.CRYPTO_ERROR, 
                     f"[CRYPTO] Invalid key size: {len(key)}, expected {CryptoConstants.AES_KEY_SIZE}")
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")

        try:
            log_event("Crypto", "[CRYPTO] Generating encryption parameters")
            nonce = secrets.token_bytes(CryptoConstants.NONCE_SIZE)
            salt = secrets.token_bytes(CryptoConstants.SALT_SIZE)
            
            log_event("Crypto", "[CRYPTO] Initializing AES-GCM cipher")
            aesgcm = AESGCM(key)
            
            log_event("Crypto", "[CRYPTO] Performing encryption")
            ciphertext_with_tag = aesgcm.encrypt(nonce, data, associated_data)
            
            log_event("Crypto", "[CRYPTO] Extracting tag and ciphertext")
            tag = ciphertext_with_tag[-16:]
            ciphertext = ciphertext_with_tag[:-16]
            
            log_event("Crypto", "[CRYPTO] Encryption completed successfully")
            return ciphertext, nonce, tag
            
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] Encryption failed: {str(e)}")
            raise RuntimeError(f"Encryption failed: {str(e)}")

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes, 
               associated_data: bytes = None) -> bytes:
        """
        Decrypt data using AES-GCM with authentication.
        
        Args:
            ciphertext: The encrypted data
            key: The decryption key
            nonce: The nonce used during encryption
            tag: The authentication tag
            associated_data: Optional authenticated associated data
            
        Returns:
            bytes: The decrypted plaintext
        """
        log_event("Crypto", "[CRYPTO] Starting AES-GCM decryption")
        
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            log_error(ErrorCode.CRYPTO_ERROR, 
                     f"[CRYPTO] Invalid key size for AES decryption: {len(key)} != {CryptoConstants.AES_KEY_SIZE}")
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")
        
        if len(nonce) != CryptoConstants.NONCE_SIZE:
            log_error(ErrorCode.CRYPTO_ERROR, 
                     f"[CRYPTO] Invalid nonce size for AES decryption: {len(nonce)} != {CryptoConstants.NONCE_SIZE}")
            raise ValueError(f"Nonce must be {CryptoConstants.NONCE_SIZE} bytes long")
        
        try:
            log_event("Crypto", "[CRYPTO] Initializing AES-GCM cipher for decryption")
            aesgcm = AESGCM(key)
            
            log_event("Crypto", "[CRYPTO] Combining ciphertext and tag for authenticated decryption")
            ciphertext_with_tag = ciphertext + tag
            
            log_event("Crypto", "[CRYPTO] Attempting AES decryption with authentication")
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
            
            log_event("Crypto", "[CRYPTO] AES decryption completed successfully")
            return plaintext
        except InvalidTag as e:
            log_error(ErrorCode.CRYPTO_ERROR, "[CRYPTO] AES decryption authentication failed")
            raise InvalidTag("Message authentication failed - possible tampering detected")
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] AES decryption failed: {e}")
            raise RuntimeError(f"Decryption failed: {e}")

    @staticmethod
    def hash(data: bytes) -> bytes:
        """Create a secure hash of data using SHA-256."""
        log_event("Crypto", "[CRYPTO] Starting hash computation")
        try:
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(data)
            result = digest.finalize()
            log_event("Crypto", "[CRYPTO] Hash computation completed successfully")
            return result
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] Hashing failed: {str(e)}")
            raise RuntimeError(f"Hashing failed: {str(e)}")

    @staticmethod
    def create_mac(key: bytes, data: bytes) -> bytes:
        """Create a MAC using HMAC-SHA256."""
        log_event("Crypto", "[CRYPTO] Starting MAC creation")
        try:
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(data)
            mac = h.finalize()
            log_event("Crypto", "[CRYPTO] MAC created successfully")
            return mac
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] MAC creation failed: {str(e)}")
            raise RuntimeError(f"MAC creation failed: {str(e)}")

    @staticmethod
    def verify_mac(key: bytes, data: bytes, mac: bytes) -> bool:
        """Verify a MAC."""
        log_event("Crypto", "[CRYPTO] Starting MAC verification")
        
        # Input validation
        if not isinstance(key, bytes) or not isinstance(data, bytes) or not isinstance(mac, bytes):
            log_error(ErrorCode.CRYPTO_ERROR, "[CRYPTO] Invalid input types for MAC verification")
            raise TypeError("All inputs must be bytes")
            
        if len(key) == 0:
            log_error(ErrorCode.CRYPTO_ERROR, "[CRYPTO] Empty key provided for MAC verification")
            raise ValueError("Key cannot be empty")
            
        if len(key) != CryptoConstants.AES_KEY_SIZE:
            log_error(ErrorCode.CRYPTO_ERROR, "[CRYPTO] Invalid key size for MAC verification")
            raise ValueError(f"Key must be {CryptoConstants.AES_KEY_SIZE} bytes long")
            
        if len(mac) == 0:
            log_error(ErrorCode.CRYPTO_ERROR, "[CRYPTO] Empty MAC provided for verification")
            raise ValueError("MAC cannot be empty")
            
        if len(mac) != CryptoConstants.MAC_SIZE:
            log_error(ErrorCode.CRYPTO_ERROR, "[CRYPTO] Invalid MAC size")
            raise ValueError(f"MAC must be {CryptoConstants.MAC_SIZE} bytes long")
            
        try:
            log_event("Crypto", "[CRYPTO] Computing HMAC for verification")
            h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
            h.update(data)
            h.verify(mac)
            log_event("Crypto", "[CRYPTO] MAC verification successful")
            return True
        except InvalidTag:
            log_error(ErrorCode.CRYPTO_ERROR, "[CRYPTO] MAC verification failed: Invalid signature")
            return False
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] MAC verification failed: {e}")
            return False

    @staticmethod
    def sign(data: bytes, private_key: bytes) -> bytes:
        """
        Sign data using ECDSA.
        
        Args:
            data: The data to sign
            private_key: The private key in PEM format
            
        Returns:
            bytes: The digital signature
        """
        try:
            log_event("Crypto", "[CRYPTO] Starting message signing")
            
            # Load the private key
            key = serialization.load_pem_private_key(
                private_key,
                password=None,
                backend=default_backend()
            )
            
            # Create signature
            signature = key.sign(
                data,
                ec.ECDSA(hashes.SHA256())
            )
            
            log_event("Crypto", "[CRYPTO] Message signed successfully")
            return signature
            
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"[CRYPTO] Signing failed: {str(e)}")
            raise RuntimeError(f"Signing failed: {str(e)}")

class EncryptionError(Exception):
    """Exception raised for encryption-related errors."""
    def __init__(self, message="Encryption operation failed"):
        self.message = message
        super().__init__(self.message)

class DecryptionError(Exception):
    """Exception raised for decryption-related errors."""
    def __init__(self, message="Decryption operation failed"):
        self.message = message
        super().__init__(self.message)