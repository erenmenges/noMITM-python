import json
import socket
import time
from Utils import log_event
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
    """
    Validate message data structure and content.
    
    Args:
        data: Dictionary containing message data
        
    Returns:
        bool: True if valid, False otherwise
    """
    required_fields = {
        'sequence': int,
        'encryptedMessage': str,
        'signature': str,
        'nonce': str,
        'timestamp': (int, float),
        'type': str,
        'iv': str
    }
    
    try:
        # Check all required fields exist and have correct types
        for field, field_type in required_fields.items():
            if field not in data:
                log_event("Validation", f"Missing required field: {field}")
                return False
            if not isinstance(data[field], field_type):
                log_event("Validation", f"Invalid type for field {field}")
                return False
                
        # Validate message size
        if len(data['encryptedMessage']) > MAX_MESSAGE_SIZE:
            log_event("Validation", "Message size exceeds maximum allowed")
            return False
            
        # Validate message type
        if not validate_message_type(data['type']):
            log_event("Validation", f"Invalid message type: {data['type']}")
            return False
            
        return True
        
    except Exception as e:
        log_event("Error", f"Message validation failed: {e}")
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
        log_event("Error", f"Failed to send data: {e}")
        raise

def receiveData(conn):
    """
    Receives data over an existing socket connection.
    
    Args:
        conn (socket.socket): The connected socket object.
    
    Returns:
        str: The received data.
    """
    try:
        chunks = []
        while True:
            chunk = conn.recv(1024)
            if not chunk:
                break
            chunks.append(chunk)
        return b''.join(chunks).decode('utf-8')
    except Exception as e:
        log_event("Error", f"Failed to receive data: {e}")
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
