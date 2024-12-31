import json
import socket
import time
from Utils import ErrorCode, log_error, log_event, ErrorMessage
import threading
from enum import Enum, auto

# Communication Module Functions

# Message Packaging and Parsing

class SequenceNumberManager:
    def __init__(self):
        self._sequence = 0
        self._lock = threading.Lock()
    
    def get_next_sequence_number(self) -> int:
        """
        Gets the next sequence number in a thread-safe manner.
        
        Returns:
            int: The next sequence number
        """
        with self._lock:
            self._sequence = (self._sequence + 1) % (2**32)  # Wrap around at 2^32
            return self._sequence

# Create a global instance
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

def packageMessage(encryptedMessage, signature, nonce, timestamp, type=MessageType.DATA, iv=""):
    """
    Creates a message package with sequence number for ordering and replay protection.
    
    Args:
        encryptedMessage: The encrypted message content
        signature: The message signature
        nonce: The message nonce
        timestamp: The message timestamp
        type: The message type
        iv: The initialization vector
        
    Returns:
        str: JSON string containing the message package
    """
    if isinstance(type, MessageType):
        type = type.value
        
    message_package = {
        "sequence": get_next_sequence_number(),
        "encryptedMessage": encryptedMessage,
        "signature": signature,
        "nonce": nonce,
        "timestamp": timestamp,
        "type": type,
        "iv": iv
    }
    return json.dumps(message_package)

def validate_message_data(data: dict) -> bool:
    """Validate message data structure and content with improved security checks."""
    try:
        # Required fields and their types
        required_fields = {
            'sequence': (int, lambda x: 0 <= x < 2**32),
            'encryptedMessage': (str, lambda x: len(x) > 0),
            'signature': (str, lambda x: len(x) > 0),
            'nonce': (str, lambda x: len(x) == 32),  # Expect 32-byte nonce in hex
            'timestamp': (int, lambda x: time.time() - 300 <= x <= time.time() + 300),  # ±5 min window
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
                
        return True
    except Exception as e:
        log_error(ErrorCode.VALIDATION_ERROR, f"Message validation failed: {e}")
        return False

def parseMessage(package):
    """
    Parses and validates a received message package.
    """
    try:
        # Parse JSON with size limit
        if len(package) > MAX_MESSAGE_SIZE:
            raise ValueError("Message size exceeds maximum allowed")
            
        data = json.loads(package)
        
        # Validate parsed data
        if not validate_message_data(data):
            raise ValueError("Invalid message format")
            
        return data
        
    except json.JSONDecodeError as e:
        log_event("Error", f"Invalid JSON format: {e}")
        raise ValueError("Malformed message")
    except Exception as e:
        log_event("Error", f"Message parsing failed: {e}")
        raise

# Network Communication

MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB

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
        MessageType(message_type)
        return True
    except ValueError:
        return False
