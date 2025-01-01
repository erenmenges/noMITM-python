import time
import logging
from enum import Enum
import secrets
import threading
from datetime import datetime

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
            log_event("Utils", "[NONCE] Starting nonce generation")
            self.cleanup_old_nonces()  # Clean up expired nonces first
            
            # If we're at capacity, force a cleanup of old nonces
            if len(self.used_nonces) >= self.max_nonces:
                log_event("Utils", f"[NONCE] Nonce storage at capacity ({self.max_nonces}), performing cleanup")
                current_time = time.time()
                self.used_nonces = {
                    nonce: timestamp 
                    for nonce, timestamp in self.used_nonces.items()
                    if current_time - timestamp <= self.cleanup_interval
                }
                log_event("Utils", f"[NONCE] After cleanup: {len(self.used_nonces)} nonces remaining")
            
            # Try to generate a unique nonce with limited retries
            for attempt in range(self.max_retries):
                nonce = secrets.token_hex(self.NONCE_SIZE)
                if nonce not in self.used_nonces:
                    log_event("Utils", f"[NONCE] Generated unique nonce after {attempt + 1} attempts")
                    return nonce
                log_event("Utils", f"[NONCE] Attempt {attempt + 1} generated duplicate nonce, retrying")
            
            # If we get here, we failed to generate a unique nonce
            log_error(
                ErrorCode.NONCE_GENERATION_ERROR,
                f"[NONCE] Failed to generate unique nonce after {self.max_retries} attempts"
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
        log_event("Utils", f"[NONCE] Starting nonce validation for: {nonce[:8]}...")
        
        if not isinstance(nonce, str):
            log_error(ErrorCode.VALIDATION_ERROR, f"[NONCE] Invalid nonce type: {type(nonce)}")
            return False
            
        if not all(c in '0123456789abcdefABCDEF' for c in nonce):
            log_error(ErrorCode.VALIDATION_ERROR, "[NONCE] Invalid nonce format: contains non-hex characters")
            return False
            
        if len(nonce) != self.NONCE_SIZE * 2:
            log_error(ErrorCode.VALIDATION_ERROR, 
                     f"[NONCE] Invalid nonce length: {len(nonce)}, expected {self.NONCE_SIZE * 2}")
            return False
            
        with self.lock:
            self.cleanup_old_nonces()
            if nonce in self.used_nonces:
                log_error(ErrorCode.VALIDATION_ERROR, "[NONCE] Nonce reuse detected")
                return False
            self.used_nonces[nonce] = time.time()
            log_event("Utils", "[NONCE] Nonce validated and stored successfully")
            return True

    def get_current_timestamp(self):
        """Retrieves the current system time."""
        timestamp = int(time.time())
        log_event("Utils", f"[TIMESTAMP] Generated timestamp: {timestamp}")
        return timestamp

    def validate_timestamp(self, timestamp, time_window=300):
        """Checks if the timestamp is within an acceptable time window."""
        log_event("Utils", f"[TIMESTAMP] Validating timestamp {timestamp} with window {time_window}s")
        current_time = self.get_current_timestamp()
        is_valid = (current_time - timestamp <= time_window and current_time >= timestamp)
        if not is_valid:
            log_error(ErrorCode.TIMESTAMP_OUT_OF_RANGE, 
                     f"[TIMESTAMP] Invalid timestamp: current={current_time}, received={timestamp}, diff={current_time-timestamp}s")
        else:
            log_event("Utils", "[TIMESTAMP] Timestamp validation successful")
        return is_valid

    def cleanup_old_nonces(self):
        """Clean up expired nonces with size limit."""
        current_time = time.time()
        if current_time - self.last_cleanup >= self.cleanup_interval:
            log_event("Utils", "[NONCE] Starting periodic nonce cleanup")
            initial_count = len(self.used_nonces)
            
            # Remove expired nonces
            expired_nonces = [
                nonce for nonce, timestamp in self.used_nonces.items()
                if current_time - timestamp > self.cleanup_interval
            ]
            for nonce in expired_nonces:
                del self.used_nonces[nonce]
            
            # If still too many nonces, remove oldest
            if len(self.used_nonces) > self.max_nonces:
                log_event("Utils", f"[NONCE] Still over capacity after expiry cleanup: {len(self.used_nonces)}")
                sorted_nonces = sorted(self.used_nonces.items(), key=lambda x: x[1])
                to_remove = len(self.used_nonces) - self.max_nonces
                for nonce, _ in sorted_nonces[:to_remove]:
                    del self.used_nonces[nonce]
                    
            self.last_cleanup = current_time
            log_event("Utils", f"[NONCE] Cleanup complete. Removed {initial_count - len(self.used_nonces)} nonces")

# Logging Mechanisms
def log_event(event_type, message):
    """Logs general events with enhanced context."""
    thread_id = threading.get_ident()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    logging.info(f"{timestamp} | Thread-{thread_id} | {event_type} | {message}")

def log_error(error_code, error_message, exc_info=False):
    """Logs errors with enhanced context and stack trace."""
    thread_id = threading.get_ident()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    logging.error(f"{timestamp} | Thread-{thread_id} | {error_code} | {error_message}", 
                 exc_info=exc_info)

def log_security_event(event_type, details):
    """Logs security-related events with enhanced context."""
    thread_id = threading.get_ident()
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
    logging.warning(f"{timestamp} | Thread-{thread_id} | SECURITY | {event_type} | {details}")

# Error Reporting
class ErrorCode(Enum):
    INVALID_NONCE = 1
    TIMESTAMP_OUT_OF_RANGE = 2
    GENERAL_ERROR = "GENERAL_ERROR"
    NETWORK_ERROR = "NETWORK_ERROR"
    CRYPTO_ERROR = 5
    SESSION_ERROR = 6
    AUTHENTICATION_ERROR = 7
    KEY_RENEWAL_ERROR = 8
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NONCE_GENERATION_ERROR = 10
    CONNECTION_ERROR = "CONNECTION_ERROR"
    SECURITY_ERROR = "SECURITY_ERROR"
    STATE_ERROR = "STATE_ERROR"
    RESOURCE_ERROR = "RESOURCE_ERROR"
    KEY_EXCHANGE_ERROR = "KEY_EXCHANGE_ERROR"
    KEY_MANAGEMENT_ERROR = "KEY_MANAGEMENT_ERROR"
    COMMUNICATION_ERROR = "COMMUNICATION_ERROR"

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
        ErrorCode.NONCE_GENERATION_ERROR: "Failed to generate a unique nonce.",
        ErrorCode.CONNECTION_ERROR: "A connection error occurred.",
        ErrorCode.SECURITY_ERROR: "A security error occurred.",
        ErrorCode.STATE_ERROR: "A state error occurred.",
        ErrorCode.RESOURCE_ERROR: "A resource error occurred.",
        ErrorCode.KEY_MANAGEMENT_ERROR: "A key management error occurred.",
        ErrorCode.COMMUNICATION_ERROR: "A communication error occurred during message exchange."
    }

def throw_error(error_code, error_message=None):
    """Throws an exception with detailed error information and logging."""
    message = error_message or ErrorMessage.messages.get(error_code, "Unknown error.")
    log_event("Utils", f"[ERROR] Throwing error: {error_code}")
    log_error(error_code, f"[ERROR] {message}")
    raise Exception(f"Error Code: {error_code.name} | Message: {message}")

class SecurityError(Exception):
    """Exception raised for security-related errors."""
    def __init__(self, message="A security error occurred"):
        self.message = message
        super().__init__(self.message)

class StateError(Exception):
    """Exception raised for state-related errors."""
    def __init__(self, message="A state error occurred"):
        self.message = message
        super().__init__(self.message)

class CommunicationError(Exception):
    """Exception raised for communication-related errors."""
    def __init__(self, message="A communication error occurred"):
        self.message = message
        super().__init__(self.message)

class TimeoutError(Exception):
    """Exception raised for timeout-related errors."""
    def __init__(self, message="Operation timed out"):
        self.message = message
        super().__init__(self.message)

class SequenceManager:
    """Manages message sequence numbers for replay protection and ordering."""
    
    def __init__(self, window_size: int = 1000):
        """Initialize sequence manager with sliding window."""
        self._lock = threading.Lock()
        self._next_sequence = 0
        self._seen_sequences = set()  # Track received sequence numbers
        self._window_size = window_size
        self._last_cleanup = time.time()
        self._cleanup_interval = 300  # 5 minutes
        
    def get_next_sequence(self) -> int:
        """Get next sequence number for outgoing messages."""
        with self._lock:
            sequence = self._next_sequence
            self._next_sequence += 1
            log_event("Utils", f"[SEQUENCE] Generated new sequence number: {sequence}")
            return sequence
            
    def validate_sequence(self, sequence: int, sender_id: str) -> bool:
        """Validate incoming message sequence number."""
        log_event("Utils", f"[SEQUENCE] Validating sequence {sequence} from sender {sender_id}")
        
        if not isinstance(sequence, int) or sequence < 0:
            log_error(ErrorCode.VALIDATION_ERROR, 
                     f"[SEQUENCE] Invalid sequence format: type={type(sequence)}, value={sequence}")
            return False
            
        with self._lock:
            # Clean up old sequences periodically
            self._cleanup_old_sequences()
            
            # Check if sequence is within acceptable window
            min_valid = max(0, self._next_sequence - self._window_size)
            if sequence < min_valid:
                log_error(ErrorCode.VALIDATION_ERROR, 
                         f"[SEQUENCE] Sequence {sequence} too old (min valid: {min_valid})")
                return False
                
            # Check if sequence is not too far in the future
            if sequence > self._next_sequence + self._window_size:
                log_error(ErrorCode.VALIDATION_ERROR, 
                         f"[SEQUENCE] Sequence {sequence} too far ahead (current: {self._next_sequence})")
                return False
                
            # Check for replay
            sequence_key = f"{sender_id}_{sequence}"
            if sequence_key in self._seen_sequences:
                log_error(ErrorCode.VALIDATION_ERROR, 
                         f"[SEQUENCE] Duplicate sequence detected: {sequence_key}")
                return False
                
            # Accept sequence
            self._seen_sequences.add(sequence_key)
            log_event("Utils", f"[SEQUENCE] Sequence {sequence} validated and stored")
            
            # Update next expected sequence if this one is higher
            if sequence >= self._next_sequence:
                self._next_sequence = sequence + 1
                log_event("Utils", f"[SEQUENCE] Updated next sequence to {self._next_sequence}")
                
            return True
            
    def _cleanup_old_sequences(self):
        """Remove old sequence numbers from tracking set."""
        current_time = time.time()
        if current_time - self._last_cleanup >= self._cleanup_interval:
            log_event("Utils", "[SEQUENCE] Starting sequence cleanup")
            initial_count = len(self._seen_sequences)
            
            min_valid_sequence = max(0, self._next_sequence - self._window_size)
            
            # Remove sequences outside the window
            self._seen_sequences = {
                seq_key for seq_key in self._seen_sequences
                if int(seq_key.split('_')[1]) >= min_valid_sequence
            }
            
            self._last_cleanup = current_time
            removed_count = initial_count - len(self._seen_sequences)
            log_event("Utils", f"[SEQUENCE] Cleanup complete. Removed {removed_count} sequences")
            
    def reset(self):
        """Reset sequence tracking state."""
        with self._lock:
            log_event("Utils", "[SEQUENCE] Resetting sequence manager state")
            self._next_sequence = 0
            self._seen_sequences.clear()
            self._last_cleanup = time.time()
            log_event("Utils", "[SEQUENCE] Sequence manager reset complete")
