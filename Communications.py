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
        """Validate received sequence number."""
        # Input validation
        if not isinstance(sequence, int):
            raise TypeError("Sequence number must be an integer")
            
        if sequence < 0 or sequence >= 2**32:
            raise ValueError("Sequence number must be between 0 and 2^32-1")
            
        if not sender_id or not isinstance(sender_id, str):
            raise ValueError("Invalid sender_id")

        # In test mode, accept all valid sequence numbers
        if self._test_mode:
            return True

        with self._lock:  # Use single lock for entire validation
            # Handle corrupted or missing state
            if sender_id not in self._sequence_window or self._sequence_window[sender_id] is None:
                self._sequence_window[sender_id] = {
                    'last': sequence,
                    'seen': set([sequence])
                }
                return True
                
            window = self._sequence_window[sender_id]
            
            # Handle sequence number wraparound
            last_seq = window['last']
            if sequence < last_seq:
                # Check if this is a legitimate wraparound
                if last_seq > 2**31 and sequence < 2**31:
                    # Valid wraparound case
                    window['last'] = sequence
                    window['seen'] = set([sequence])
                    return True
                # Otherwise, it's too old
                return False
                
            # Normal sequence validation
            if sequence - last_seq > self._window_size:
                return False  # Too far ahead
                
            if sequence in window['seen']:
                return False  # Replay detected
                
            window['seen'].add(sequence)
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
    KEY_EXCHANGE = "KEY_EXCHANGE"
    KEY_EXCHANGE_RESPONSE = "KEY_EXCHANGE_RESPONSE"
    DATA = "DATA"
    ACKNOWLEDGE = "ACKNOWLEDGE" 
    SERVER_RESPONSE = "SERVER_RESPONSE"
    ERROR = "ERROR"
    KEY_RENEWAL_REQUEST = "KEY_RENEWAL_REQUEST"
    KEY_RENEWAL_RESPONSE = "KEY_RENEWAL_RESPONSE"
    SESSION_TERMINATION = "SESSION_TERMINATION"
    KEEPALIVE = "KEEPALIVE"
    STATE_VERIFICATION = "STATE_VERIFICATION"
    STATE_RESPONSE = "STATE_RESPONSE"

def packageMessage(encryptedMessage: str, signature: str, nonce: str, timestamp: int, 
                  type: str, tag: str = None, version: int = 1, sender_id: str = None,
                  sequence: int = None) -> bytes:
    """Package a message with all required fields."""
    # Get sequence number if not provided
    if sequence is None:
        sequence = get_next_sequence_number()
        
    # Ensure sender_id has a value
    if sender_id is None:
        sender_id = "system"
        
    message = {
        'type': type,
        'encryptedMessage': encryptedMessage,
        'nonce': nonce,
        'timestamp': timestamp,
        'version': version,
        'tag': tag,
        'sender_id': sender_id,
        'sequence': sequence,
        'signature': signature.hex() if isinstance(signature, bytes) else signature
    }
    
    # Validate required fields are present
    required_fields = ['type', 'encryptedMessage', 'nonce', 'timestamp', 'signature']
    for field in required_fields:
        if message.get(field) is None:
            raise ValueError(f"Required field '{field}' is missing")
    
    # Remove None values for optional fields
    message = {k: v for k, v in message.items() if v is not None}
    
    log_event("Communications", f"[COMMUNICATIONS] Packaging message with fields: {list(message.keys())}")
    return json.dumps(message).encode('utf-8')

def validate_message_data(data: dict, sequence_manager=None) -> bool:
    """Validate message data structure and required fields."""
    try:
        # Required fields that must be present
        required_fields = [
            'type', 
            'encryptedMessage', 
            'nonce', 
            'timestamp', 
            'signature'
        ]
        
        # Check all required fields are present
        for field in required_fields:
            if field not in data:
                log_error(ErrorCode.VALIDATION_ERROR, f"Validation failed for field {field}")
                return False
                
        # Validate message type
        if not validate_message_type(data['type']):
            log_error(ErrorCode.VALIDATION_ERROR, "Invalid message type")
            return False
            
        # Validate timestamp is reasonable
        current_time = int(time.time())
        message_time = int(data['timestamp'])
        if abs(current_time - message_time) > 300:  # 5 minute window
            log_error(ErrorCode.VALIDATION_ERROR, "Message timestamp too old or too far in future")
            return False
            
        # Validate sequence if manager provided
        if sequence_manager and 'sequence' in data:
            if not sequence_manager.validate_sequence(data['sequence'], data.get('sender_id', 'unknown')):
                log_error(ErrorCode.VALIDATION_ERROR, "Invalid message sequence")
                return False
                
        return True
        
    except Exception as e:
        log_error(ErrorCode.VALIDATION_ERROR, f"Message validation failed: {str(e)}")
        return False

MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB maximum message size

def sendData(sock: socket.socket, data: bytes | str) -> bool:
    """Send data over socket with proper encoding."""
    log_event("Communications", "[COMMUNICATIONS] Starting data send operation")
    
    try:
        log_event("Communications", f"[COMMUNICATIONS] Input data type: {type(data)}")
        
        if isinstance(data, str):
            log_event("Communications", "[COMMUNICATIONS] Converting string data to bytes")
            data = data.encode('utf-8')
            log_event("Communications", f"[COMMUNICATIONS] String encoded to {len(data)} bytes")
        elif not isinstance(data, bytes):
            log_error(ErrorCode.VALIDATION_ERROR, 
                     f"[COMMUNICATIONS] Invalid data type: {type(data)}, expected string or bytes")
            raise ValueError("Data must be string or bytes")
            
        # Add newline as message delimiter
        if not data.endswith(b'\n'):
            log_event("Communications", "[COMMUNICATIONS] Adding newline delimiter to message")
            data += b'\n'
            
        log_event("Communications", f"[COMMUNICATIONS] Attempting to send {len(data)} bytes")
        sock.sendall(data)
        log_event("Communications", "[COMMUNICATIONS] Data sent successfully")
        return True
        
    except socket.error as e:
        log_error(ErrorCode.NETWORK_ERROR, 
                 f"[COMMUNICATIONS] Socket error during send: {str(e)}")
        raise
    except Exception as e:
        log_error(ErrorCode.NETWORK_ERROR, 
                 f"[COMMUNICATIONS] Failed to send data: {str(e)}")
        raise

def receiveData(conn: socket.socket) -> bytes:
    """
    Receives data from a socket.
    
    Args:
        conn: The socket to receive data from
        
    Returns:
        bytes: The received data
        
    Raises:
        socket.error: If there is an issue with the socket
    """
    log_event("Communications", f"[COMMUNICATIONS] Starting data receive from {conn.getpeername()}")
    
    try:
        data = b''
        total_chunks = 0
        log_event("Communications", "[COMMUNICATIONS] Initialized receive buffer")
        
        while True:
            log_event("Communications", f"[COMMUNICATIONS] Attempting to receive chunk {total_chunks + 1}")
            chunk = conn.recv(4096)
            
            if not chunk:
                log_event("Communications", f"[COMMUNICATIONS] Connection closed by peer {conn.getpeername()}")
                break
                
            data += chunk
            total_chunks += 1
            log_event("Communications", 
                     f"[COMMUNICATIONS] Received chunk {total_chunks} of size {len(chunk)} bytes. "
                     f"Total received: {len(data)} bytes")
            
            if len(chunk) < 4096:
                log_event("Communications", 
                         f"[COMMUNICATIONS] Chunk smaller than buffer size ({len(chunk)} < 4096), "
                         "indicating end of transmission")
                break
        
        if total_chunks == 0:
            log_event("Communications", "[COMMUNICATIONS] No data received before connection closed")
        else:
            log_event("Communications", 
                     f"[COMMUNICATIONS] Data receive complete. Total chunks: {total_chunks}, "
                     f"Total bytes: {len(data)}")
        
        return data
        
    except socket.error as e:
        log_error(ErrorCode.NETWORK_ERROR, 
                 f"[COMMUNICATIONS] Socket error during receive from {conn.getpeername()}: {e}")
        raise
    except Exception as e:
        log_error(ErrorCode.NETWORK_ERROR, 
                 f"[COMMUNICATIONS] Unexpected error during receive from {conn.getpeername()}: {e}")
        raise

# Key Renewal Messages

def sendKeyRenewalRequest(peer, newPublicKey):
    """Send a key renewal request to the specified peer."""
    key_renewal_message = json.dumps({
        "type": MessageType.KEY_RENEWAL_REQUEST.value,
        "newPublicKey": newPublicKey,
        "timestamp": int(time.time())
    })
    sendData(peer, key_renewal_message)

def handleKeyRenewalResponse(message: str) -> dict:
    """
    Handle key renewal response message.
    
    Args:
        message: JSON string containing the key renewal response
        
    Returns:
        dict: Parsed response data
        
    Raises:
        ValueError: If message is invalid or has wrong type
    """
    data = json.loads(message)
    if data.get("type") != MessageType.KEY_RENEWAL_RESPONSE.value:
        raise ValueError("Invalid message type for key renewal response")
    return data

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
    log_event("Communications", "[COMMUNICATIONS] Starting message parsing")
    
    try:
        # Check package type
        log_event("Communications", f"[COMMUNICATIONS] Checking package type: {type(package)}")
        if not isinstance(package, (str, bytes)):
            log_error(ErrorCode.VALIDATION_ERROR, 
                     f"[COMMUNICATIONS] Invalid package type: {type(package)}, expected string or bytes")
            raise ValueError("Invalid message format: expected string or bytes")
            
        # Convert bytes to string if needed
        if isinstance(package, bytes):
            log_event("Communications", "[COMMUNICATIONS] Converting bytes package to string")
            package = package.decode('utf-8')
            log_event("Communications", f"[COMMUNICATIONS] Package decoded, length: {len(package)} characters")
            
        # Parse JSON with size limit
        log_event("Communications", f"[COMMUNICATIONS] Checking message size: {len(package)} bytes")
        if len(package) > MAX_MESSAGE_SIZE:
            log_error(ErrorCode.VALIDATION_ERROR, 
                     f"[COMMUNICATIONS] Message size {len(package)} exceeds limit of {MAX_MESSAGE_SIZE}")
            raise ValueError(f"Message size exceeds maximum allowed size of {MAX_MESSAGE_SIZE} bytes")
            
        log_event("Communications", "[COMMUNICATIONS] Attempting to parse JSON data")
        data = json.loads(package)
        log_event("Communications", f"[COMMUNICATIONS] JSON parsed successfully: {len(str(data))} bytes")
        
        # Validate parsed data using the provided sequence manager
        log_event("Communications", "[COMMUNICATIONS] Starting message data validation")
        if sequence_manager:
            log_event("Communications", "[COMMUNICATIONS] Using provided sequence manager for validation")
        
        if not validate_message_data(data, sequence_manager=sequence_manager):
            log_error(ErrorCode.VALIDATION_ERROR, 
                     f"[COMMUNICATIONS] Message validation failed for data structure: {list(data.keys())}")
            raise ValueError("Invalid message format")
            
        log_event("Communications", "[COMMUNICATIONS] Message parsed and validated successfully")
        log_event("Communications", f"[COMMUNICATIONS] Message content: {data}")
        return data
        
    except json.JSONDecodeError as e:
        log_error(ErrorCode.VALIDATION_ERROR, 
                 f"[COMMUNICATIONS] JSON parsing failed: {str(e)}, at position {e.pos}")
        raise ValueError("Malformed message")
    except ValueError as e:
        log_error(ErrorCode.VALIDATION_ERROR, f"[COMMUNICATIONS] Validation error: {str(e)}")
        raise
    except Exception as e:
        log_error(ErrorCode.GENERAL_ERROR, 
                 f"[COMMUNICATIONS] Unexpected error during message parsing: {type(e).__name__}: {str(e)}")
        raise
