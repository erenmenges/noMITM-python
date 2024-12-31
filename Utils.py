import time
import logging
from enum import Enum

# Initialize logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Nonce and Timestamp Management
class NonceManager:
    def __init__(self):
        self.used_nonces = set()

    def generate_nonce(self):
        """Generates a unique nonce."""
        nonce = f"{time.time()}-{id(self)}"
        return nonce

    def validate_nonce(self, nonce):
        """Validates that the nonce has not been used before."""
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
        return abs(current_time - timestamp) <= time_window

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

class ErrorMessage:
    messages = {
        ErrorCode.INVALID_NONCE: "The provided nonce is invalid or has already been used.",
        ErrorCode.TIMESTAMP_OUT_OF_RANGE: "The provided timestamp is outside the acceptable time window.",
        ErrorCode.GENERAL_ERROR: "An unspecified error occurred.",
    }

def throw_error(error_code, error_message=None):
    """Throws an exception with detailed error information."""
    message = error_message or ErrorMessage.messages.get(error_code, "Unknown error.")
    log_error(error_code, message)
    raise Exception(f"Error Code: {error_code.name} | Message: {message}")
