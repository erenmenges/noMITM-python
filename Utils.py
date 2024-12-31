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
        self.used_nonces = set()
        self.lock = threading.Lock()  # To handle concurrency

    def generate_nonce(self):
        """Generates a cryptographically secure unique nonce."""
        with self.lock:
            while True:
                nonce = secrets.token_hex(16)
                if nonce not in self.used_nonces:
                    self.used_nonces.add(nonce)
                    return nonce

    def validate_nonce(self, nonce):
        """Validates that the nonce has not been used before."""
        with self.lock:
            if nonce in self.used_nonces:
                return False
            self.used_nonces.add(nonce)
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
        with self.lock:
            if len(self.used_nonces) > 10000:  # Arbitrary limit
                self.used_nonces.clear()

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

class ErrorMessage:
    messages = {
        ErrorCode.INVALID_NONCE: "The provided nonce is invalid or has already been used.",
        ErrorCode.TIMESTAMP_OUT_OF_RANGE: "The provided timestamp is outside the acceptable time window.",
        ErrorCode.GENERAL_ERROR: "An unspecified error occurred.",
        ErrorCode.NETWORK_ERROR: "A network communication error occurred.",
        ErrorCode.CRYPTO_ERROR: "A cryptographic operation failed.",
        ErrorCode.SESSION_ERROR: "A session management error occurred.",
        ErrorCode.AUTHENTICATION_ERROR: "Authentication failed.",
        ErrorCode.KEY_RENEWAL_ERROR: "Key renewal process failed."
    }

def throw_error(error_code, error_message=None):
    """Throws an exception with detailed error information."""
    message = error_message or ErrorMessage.messages.get(error_code, "Unknown error.")
    log_error(error_code, message)
    raise Exception(f"Error Code: {error_code.name} | Message: {message}")
