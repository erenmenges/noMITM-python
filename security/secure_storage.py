from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
from typing import Optional, Dict
import threading

class SecureStorage:
    """Secure storage for cryptographic material with memory protection."""
    
    def __init__(self):
        self._lock = threading.Lock()
        self._storage: Dict[str, bytes] = {}
        self._key = self._generate_storage_key()
        self._fernet = Fernet(self._key)
        
    def _generate_storage_key(self) -> bytes:
        """Generate a secure storage key."""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(os.urandom(32)))
        return key
        
    def store(self, key: str, data: bytes) -> None:
        """Store encrypted data."""
        with self._lock:
            encrypted = self._fernet.encrypt(data)
            self._storage[key] = encrypted
            
    def retrieve(self, key: str) -> Optional[bytes]:
        """Retrieve and decrypt data."""
        with self._lock:
            if key not in self._storage:
                return None
            encrypted = self._storage[key]
            return self._fernet.decrypt(encrypted)
            
    def remove(self, key: str) -> None:
        """Remove a key with timeout."""
        try:
            if self._lock.acquire(timeout=2):  # Add timeout to prevent deadlock
                try:
                    if key in self._storage:
                        del self._storage[key]
                finally:
                    self._lock.release()
        except Exception as e:
            log_error(ErrorCode.STORAGE_ERROR, f"Error removing key from secure storage: {e}")
            
    def clear(self) -> None:
        """Clear all stored data with timeout."""
        try:
            if self._lock.acquire(timeout=2):  # Add timeout to prevent deadlock
                try:
                    keys = list(self._storage.keys())  # Create a copy of keys
                    for key in keys:
                        try:
                            del self._storage[key]
                        except KeyError:
                            pass  # Key might have been removed by another thread
                finally:
                    self._lock.release()
        except Exception as e:
            log_error(ErrorCode.STORAGE_ERROR, f"Error clearing secure storage: {e}") 