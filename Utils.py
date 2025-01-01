import time
import logging
from enum import Enum
import secrets
import threading

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Nonce and Timestamp Management
class NonceManager:
    def __init__(self):
        self.used_nonces = {}  # Dictionary for timestamps
        self.lock = threading.Lock()
        self.cleanup_interval = 300  # 5 minutes
        self.last_cleanup = time.time()
        self.max_nonces = 10000  # Maximum number of stored nonces
        self.max_retries = 100   # Maximum number of retry attempts
        self.NONCE_SIZE = 12     # 12 bytes (96 bits) for GCM mode
        
    def generate_nonce(self) -> str:
        """
        Generates a cryptographically secure unique nonce.
        
        Returns:
            str: A unique nonce in hex format (24 characters for 12 bytes)
            
        Raises:
            RuntimeError: If unable to generate a unique nonce after max retries
        """
        with self.lock:
            self.cleanup_old_nonces()  # Clean up expired nonces first
            
            # If we're at capacity, force a cleanup of old nonces
            if len(self.used_nonces) >= self.max_nonces:
                current_time = time.time()
                self.used_nonces = {
                    nonce: timestamp 
                    for nonce, timestamp in self.used_nonces.items()
                    if current_time - timestamp <= self.cleanup_interval
                }
            
            # Try to generate a unique nonce with limited retries
            for _ in range(self.max_retries):
                nonce = secrets.token_hex(self.NONCE_SIZE)
                if nonce not in self.used_nonces:
                    # Don't store the nonce here, let validate_nonce handle it
                    return nonce
                    
            # If we get here, we failed to generate a unique nonce
            log_error(
                ErrorCode.NONCE_GENERATION_ERROR,
                f"Failed to generate unique nonce after {self.max_retries} attempts"
            )
            raise RuntimeError("Unable to generate unique nonce")

    def validate_nonce(self, nonce: str) -> bool:
        """
        Validates that the nonce has not been used before and stores it if valid.
        
        Args:
            nonce: The nonce to validate
            
        Returns:
            bool: True if nonce is valid and not previously used, False otherwise
        """
        if not isinstance(nonce, str):
            return False
            
        if not all(c in '0123456789abcdefABCDEF' for c in nonce):
            return False
            
        if len(nonce) != self.NONCE_SIZE * 2:  # Hex string is twice the byte length
            return False
            
        with self.lock:
            self.cleanup_old_nonces()
            if nonce in self.used_nonces:
                return False
            self.used_nonces[nonce] = time.time()
            return True

    def get_current_timestamp(self):
        """Retrieves the current system time."""
        return int(time.time())

    def validate_timestamp(self, timestamp, time_window=300):
        """Checks if the timestamp is within an acceptable time window (default: 5 minutes)."""
        current_time = self.get_current_timestamp()
        return (current_time - timestamp <= time_window and 
                current_time >= timestamp)  # Also check that timestamp isn't from future

    def cleanup_old_nonces(self):
        """Clean up expired nonces with size limit."""
        current_time = time.time()
        if current_time - self.last_cleanup >= self.cleanup_interval:
            # Remove expired nonces
            expired_nonces = [
                nonce for nonce, timestamp in self.used_nonces.items()
                if current_time - timestamp > self.cleanup_interval
            ]
            for nonce in expired_nonces:
                del self.used_nonces[nonce]
            
            # If still too many nonces, remove oldest
            if len(self.used_nonces) > self.max_nonces:
                sorted_nonces = sorted(self.used_nonces.items(), 
                                    key=lambda x: x[1])
                to_remove = len(self.used_nonces) - self.max_nonces
                for nonce, _ in sorted_nonces[:to_remove]:
                    del self.used_nonces[nonce]
                    
            self.last_cleanup = current_time

# Logging Mechanisms
def log_event(event_type, message):
    """Logs general events."""
    logging.info(f"Event Type: {event_type} | Message: {message}")

def log_error(error_code, error_message):
    """Logs errors with specific codes and messages."""
    logging.error(f"Error Code: {error_code} | Error Message: {error_message}")

def log_security_event(event_type, details):
    """Logs security-related events."""
    logging.warning(f"Security Event Type: {event_type} | Details: {details}")

# Error Reporting
class ErrorCode(Enum):
    INVALID_NONCE = 1
    TIMESTAMP_OUT_OF_RANGE = 2
    GENERAL_ERROR = 3
    NETWORK_ERROR = 4
    CRYPTO_ERROR = 5
    SESSION_ERROR = 6
    AUTHENTICATION_ERROR = 7
    KEY_RENEWAL_ERROR = 8
    VALIDATION_ERROR = 9
    NONCE_GENERATION_ERROR = 10

class ErrorMessage:
    messages = {
        ErrorCode.INVALID_NONCE: "The provided nonce is invalid or has already been used.",
        ErrorCode.TIMESTAMP_OUT_OF_RANGE: "The provided timestamp is outside the acceptable time window.",
        ErrorCode.GENERAL_ERROR: "An unspecified error occurred.",
        ErrorCode.NETWORK_ERROR: "A network communication error occurred.",
        ErrorCode.CRYPTO_ERROR: "A cryptographic operation failed.",
        ErrorCode.SESSION_ERROR: "A session management error occurred.",
        ErrorCode.AUTHENTICATION_ERROR: "Authentication failed.",
        ErrorCode.KEY_RENEWAL_ERROR: "Key renewal process failed.",
        ErrorCode.NONCE_GENERATION_ERROR: "Failed to generate a unique nonce."
    }

def throw_error(error_code, error_message=None):
    """Throws an exception with detailed error information."""
    message = error_message or ErrorMessage.messages.get(error_code, "Unknown error.")
    log_error(error_code, message)
    raise Exception(f"Error Code: {error_code.name} | Message: {message}")
