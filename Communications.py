import json
import socket
import time
from Utils import ErrorCode, log_error, log_event, ErrorMessage
import threading
from enum import Enum, auto

# Communication Module Functions

# Message Packaging and Parsing

class SequenceNumberManager:
    def __init__(self, test_mode=False):
        self._sequence = 0
        self._lock = threading.Lock()
        self._sequence_window = {}  # Track received sequences
        self._window_size = 1000  # Window size for replay protection
        self._test_mode = test_mode
        
    def get_next_sequence_number(self) -> int:
        """
        Gets the next sequence number in a thread-safe manner.
        
        Returns:
            int: The next sequence number
        """
        with self._lock:
            self._sequence = (self._sequence + 1) % (2**32)  # Wrap around at 2^32
            return self._sequence
            
    def validate_sequence(self, sequence: int, sender_id: str) -> bool:
        """
        Validate received sequence number.
        
        Args:
            sequence: The sequence number to validate
            sender_id: The ID of the sender
            
        Returns:
            bool: True if sequence is valid, False otherwise
        """
        with self._lock:
            if sender_id not in self._sequence_window:
                self._sequence_window[sender_id] = {
                    'last': sequence,
                    'seen': set([sequence])
                }
                return True
                
            window = self._sequence_window[sender_id]
            
            # Always check window bounds
            if sequence <= window['last'] - self._window_size:
                return False  # Too old
                
            # In test mode, only check window bounds, allow replays
            if self._test_mode:
                if sequence > window['last']:
                    window['last'] = sequence
                return True
                
            # In production mode, check for replays
            if sequence in window['seen']:
                return False  # Replay detected
                
            window['seen'].add(sequence)
            if sequence > window['last']:
                window['last'] = sequence
                # Clean up old sequences
                window['seen'] = {s for s in window['seen'] 
                                if s > sequence - self._window_size}
            return True

# Create a global instance for production use
_sequence_manager = SequenceNumberManager()

def get_next_sequence_number() -> int:
    """
    Gets the next message sequence number.
    
    Returns:
        int: The next sequence number
    """
    return _sequence_manager.get_next_sequence_number()

class MessageType(Enum):
    DATA = "data"
    KEY_RENEWAL_REQUEST = "keyRenewalRequest"
    KEY_RENEWAL_RESPONSE = "keyRenewalResponse"
    SESSION_TERMINATION = "sessionTermination"
    ACKNOWLEDGE = "acknowledge"
    ERROR = "error"

def packageMessage(encryptedMessage, signature, nonce, timestamp, type="data", iv="", tag=""):
    """Package message with sequence number for replay protection."""
    message_data = {
        "sequence": get_next_sequence_number(),  # Add sequence number
        "encryptedMessage": encryptedMessage,
        "signature": signature,
        "nonce": nonce,
        "timestamp": timestamp,
        "type": type,
        "iv": iv,
        "tag": tag
    }
    return json.dumps(message_data)

def validate_message_data(data: dict, sequence_manager=None) -> bool:
    """Validate message data structure and content with improved security checks."""
    try:
        # Use provided sequence manager in tests, otherwise use global instance
        seq_manager = sequence_manager or _sequence_manager
        
        # Add sender_id validation
        sender_id = data.get('sender_id')
        if not sender_id:
            log_error(ErrorCode.VALIDATION_ERROR, "Missing sender_id in message")
            return False
            
        # Required fields and their types
        required_fields = {
            'sequence': (int, lambda x: 0 <= x < 2**32),
            'encryptedMessage': (str, lambda x: len(x) > 0),
            'signature': (str, lambda x: len(x) == 128),  # Expect 64-byte signature in hex
            'nonce': (str, lambda x: len(x) == 32),  # Expect 32-byte nonce in hex
            'timestamp': (int, lambda x: time.time() - 300 <= x <= time.time() + 300),
            'type': (str, lambda x: validate_message_type(x)),
        }
        
        # Check all required fields exist and have correct types
        for field, (field_type, validator) in required_fields.items():
            if field not in data:
                log_error(ErrorCode.VALIDATION_ERROR, f"Missing required field: {field}")
                return False
            if not isinstance(data[field], field_type):
                log_error(ErrorCode.VALIDATION_ERROR, f"Invalid type for field {field}")
                return False
            if not validator(data[field]):
                log_error(ErrorCode.VALIDATION_ERROR, f"Validation failed for field {field}")
                return False
        
        # Validate sequence number after basic validation passes
        sequence = data.get('sequence')
        if not seq_manager.validate_sequence(sequence, sender_id):
            log_error(ErrorCode.VALIDATION_ERROR, "Invalid sequence number")
            return False
            
        # Additional security checks
        if 'iv' in data and not isinstance(data['iv'], str):
            log_error(ErrorCode.VALIDATION_ERROR, "Invalid IV format")
            return False
        if 'tag' in data and not isinstance(data['tag'], str):
            log_error(ErrorCode.VALIDATION_ERROR, "Invalid tag format")
            return False
                
        return True
    except Exception as e:
        log_error(ErrorCode.VALIDATION_ERROR, f"Message validation failed: {e}")
        return False

MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB maximum message size

def sendData(conn, data):
    """
    Sends data over an existing socket connection.

    Args:
        conn (socket.socket): The connected socket object.
        data (str): The data to send.
    
    Returns:
        None
    """
    try:
        if isinstance(data, str):
            data = data.encode('utf-8')
        if len(data) > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message size exceeds maximum allowed size of {MAX_MESSAGE_SIZE} bytes")
        conn.sendall(data)
    except socket.error as e:
        log_error(ErrorCode.NETWORK_ERROR, f"Failed to send data: {e}")
        raise
    except Exception as e:
        log_error(ErrorCode.GENERAL_ERROR, f"Unexpected error while sending data: {e}")
        raise

def receiveData(conn, timeout=30, max_size=1024*1024):
    """Receives data with proper timeout and size limits."""
    try:
        chunks = []
        total_size = 0
        conn.settimeout(timeout)
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                chunk = conn.recv(4096)  # Increased buffer size for efficiency
                if not chunk:
                    if not chunks:
                        raise ConnectionError("Connection closed by peer")
                    break
                    
                total_size += len(chunk)
                if total_size > max_size:
                    raise ValueError(f"Message size exceeds maximum allowed size of {max_size} bytes")
                    
                chunks.append(chunk)
            except socket.timeout:
                if chunks:  # If we have partial data
                    break
                continue
                
        if not chunks:
            raise TimeoutError("No data received within timeout period")
            
        return b''.join(chunks).decode('utf-8')
    except Exception as e:
        log_error(ErrorCode.NETWORK_ERROR, f"Failed to receive data: {e}")
        raise

# Key Renewal Messages

def sendKeyRenewalRequest(peer, newPublicKey):
    # Package the key renewal request as JSON
    key_renewal_message = json.dumps({
        "type": "keyRenewalRequest",
        "newPublicKey": newPublicKey,
        "timestamp": time.time()
    })
    # Send the key renewal request using the sendData function
    sendData(peer, key_renewal_message)

def handleKeyRenewalResponse(message):
    # Parse the incoming message
    response = parseMessage(message)
    # Validate the response type
    if response.get("type") != "keyRenewalResponse":
        raise ValueError("Invalid message type for key renewal response.")
    # Return the parsed response
    return response

def validate_message_type(message_type: str) -> bool:
    """Validate that the message type is recognized."""
    try:
        # Convert string values to lowercase for case-insensitive comparison
        message_type = message_type.lower()
        valid_types = {member.value.lower() for member in MessageType}
        return message_type in valid_types
    except Exception as e:
        log_error(ErrorCode.VALIDATION_ERROR, f"Message type validation failed: {e}")
        return False

def parseMessage(package, sequence_manager=None):
    """
    Parses and validates a received message package.
    
    Args:
        package: The message package to parse
        sequence_manager: Optional sequence manager for testing
    """
    try:
        # Check package type
        if not isinstance(package, (str, bytes)):
            raise ValueError("Invalid message format: expected string or bytes")
            
        # Convert bytes to string if needed
        if isinstance(package, bytes):
            package = package.decode('utf-8')
            
        # Parse JSON with size limit
        if len(package) > MAX_MESSAGE_SIZE:
            raise ValueError(f"Message size exceeds maximum allowed size of {MAX_MESSAGE_SIZE} bytes")
            
        data = json.loads(package)
        
        # Validate parsed data using the provided sequence manager
        if not validate_message_data(data, sequence_manager=sequence_manager):
            raise ValueError("Invalid message format")
            
        return data
        
    except json.JSONDecodeError as e:
        log_error(ErrorCode.VALIDATION_ERROR, f"Invalid JSON format: {e}")
        raise ValueError("Malformed message")
    except ValueError as e:
        log_error(ErrorCode.VALIDATION_ERROR, str(e))
        raise
    except Exception as e:
        log_error(ErrorCode.GENERAL_ERROR, f"Message parsing failed: {e}")
        raise
