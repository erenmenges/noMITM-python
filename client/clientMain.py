import threading
import socket
import json
import os
from typing import Optional, Tuple
from datetime import datetime
import time
from contextlib import contextmanager
import ssl
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID, AuthorityInformationAccessOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Local imports
from Communications import (
    packageMessage, 
    parseMessage, 
    sendData, 
    receiveData, 
    MessageType, 
    MAX_MESSAGE_SIZE
)
from Crypto import (
    Crypto, 
    SecureMessage, 
    EncryptionError, 
    CryptoConstants
)
from KeyManagement import KeyManagement
from Utils import (
    NonceManager, 
    log_event, 
    log_error, 
    ErrorCode, 
    ErrorMessage, 
    throw_error, 
    SequenceManager,
    SecurityError,
    StateError,
    CommunicationError,
    TimeoutError
)
from security.TLSWrapper import TLSWrapper, TLSConfig
from security.secure_storage import SecureStorage

class Client:
    """
    Secure client implementation for encrypted communication.
    
    This class handles secure communication with a server, including:
    - TLS certificate validation
    - Key exchange and verification
    - Message encryption and signing
    - Replay attack prevention
    - Session management
    
    Attributes:
        connection_timeout (int): Connection timeout in seconds
        message_timeout (int): Maximum allowed message age in seconds
        max_message_size (int): Maximum allowed message size in bytes
    """

    def __init__(self, tls_config=None):
        """Initialize the client with secure defaults."""
        self._lock = threading.Lock()
        self._connection_timeout = 30
        self._message_timeout = 300
        self._max_message_size = 1024 * 1024
        
        # Initialize TLS config
        self.tls_config = tls_config or TLSConfig(enabled=False)
        
        # Initialize secure storage ONCE
        self._secure_storage = SecureStorage()
        
        # Initialize state
        self._state = {
            'connection_state': 'disconnected',
            'session_established': False,
            'key_exchange_complete': False,
            'certificate_verified': False,
            'last_server_sequence': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'last_key_renewal': 0,
            'encryption_failures': 0,
            'reconnection_attempts': 0,
            'last_activity': time.time()
        }
        
        # Initialize locks ONCE
        self._state_lock = threading.RLock()  # Use RLock for state operations
        self._send_lock = threading.Lock()
        self._key_lock = threading.Lock()
        self._storage_lock = threading.Lock()
        self._handler_lock = threading.Lock()
        self._activity_lock = threading.Lock()
        
        # Initialize managers
        self.secure_storage = SecureStorage()
        self.key_manager = KeyManagement(self.secure_storage)
        self.nonce_manager = NonceManager()
        self.sequence_manager = SequenceManager()
        self._connected = False
        
        # Initialize connection state
        self.listening = False
        self.listen_thread = None
        self.destination = None
        self.socket = None
        self.max_encryption_failures = 3
        self.max_retries = 3
        self.retry_delay = 1  # seconds
        self._last_activity = 0
        self._activity_timeout = 300  # 5 minutes
        self._heartbeat_interval = 15  # Send heartbeat every 15 seconds
        self._heartbeat_thread = None
        self._cleanup_thread = None
        self._cleanup_interval = 30  # 30 seconds
        
        # Error handling callbacks
        self._error_handlers = []
        self._state_change_handlers = []
        
        # Timeout configurations
        self._operation_timeouts = {
            'connect': 30,
            'handshake': 20,
            'key_exchange': 30,
            'send': 15,
            'receive': 10,
            'renewal': 25,
            'verification': 15,
            'termination': 10
        }
        self._retry_config = {
            'max_retries': 3,
            'backoff_factor': 1.5,
            'max_delay': 10
        }
        
        # Resource tracking
        self._resources = {
            'socket': None,
            'threads': set(),
            'temp_files': set(),
            'key_material': set(),
            'buffers': []
        }
        self._resource_lock = threading.RLock()
        
        # Generate keys if needed
        if not self.key_manager.has_key_pair():
            self.key_manager.generate_key_pair()

        self._listener_thread = None
        self._listener_lock = threading.Lock()
        
        self._shutting_down = False  # Initialize shutdown flag to control the listener thread
        

    def _notify_state_change(self, new_state: bool):
        """Notify all registered state change handlers."""
        with self._handler_lock:
            for handler in self._state_change_handlers:
                try:
                    handler(new_state)
                except Exception as e:
                    log_error(ErrorCode.CALLBACK_ERROR, f"State change handler failed: {e}")


    def get_session_key(self) -> Optional[bytes]:
        """Retrieve the session key."""
        try:
            with self._storage_lock:
                key_data = self._secure_storage.retrieve('session_key')
                if key_data:
                    # Parse the JSON data
                    data_dict = json.loads(key_data.decode('utf-8'))
                    # Convert hex string back to bytes
                    return bytes.fromhex(data_dict['key'])
            return None
        except Exception as e:
            log_error(ErrorCode.KEY_MANAGEMENT_ERROR, f"[SECURE_SESSION] Failed to retrieve session key: {str(e)}")
            return None

    def is_connected(self) -> bool:
        """Check if client has active connection."""
        with self._state_lock:
            try:
                if not self._connected or not self.socket:
                    return False
                    
                # Check socket validity
                original_timeout = self.socket.gettimeout()
                try:
                    self.socket.settimeout(1)
                    # Try to read with zero length to check connection
                    self.socket.recv(0)
                    return True
                except socket.timeout:
                    # Timeout is okay - connection is still alive
                    return True
                except Exception:
                    # Other errors indicate connection issues
                    return False
                finally:
                    # Restore original timeout
                    if self.socket:
                        self.socket.settimeout(original_timeout)
                
            except Exception:
                return False

    def establish_secure_session(self, destination: Tuple[str, int]) -> bool:
        """Establish a secure session with the server."""
        try:
            log_event("Session", f"[SECURE_SESSION] Starting secure session establishment with {destination[0]}:{destination[1]}")
            
            # Store destination for later use
            self.destination = destination
            log_event("Session", f"[SECURE_SESSION] Stored destination: {destination}")
            
            # Create socket
            try:
                log_event("Session", "[SECURE_SESSION] Creating new socket")
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                log_event("Session", "[SECURE_SESSION] Socket created successfully")
                
                log_event("Session", f"[SECURE_SESSION] Setting socket timeout to {self._connection_timeout}s")
                self.socket.settimeout(self._connection_timeout)
                log_event("Session", f"[SECURE_SESSION] Socket timeout set successfully")
                
                log_event("Session", f"[SECURE_SESSION] Attempting connection to {destination[0]}:{destination[1]}")
                self.socket.connect(destination)
                log_event("Session", "[SECURE_SESSION] TCP connection established successfully")
                
                # Log socket details
                local_addr = self.socket.getsockname()
                log_event("Session", f"[SECURE_SESSION] Local endpoint: {local_addr[0]}:{local_addr[1]}")
                log_event("Session", f"[SECURE_SESSION] Remote endpoint: {destination[0]}:{destination[1]}")
                
                # Wrap socket with TLS if enabled
                if self.tls_config and self.tls_config.enabled:
                    log_event("Security", "[SECURE_SESSION] Wrapping socket with TLS using TLSWrapper")
                    try:
                        tls_wrapper = TLSWrapper(self.tls_config, client_mode=True)
                        self.socket = tls_wrapper.wrap_socket(
                            self.socket,
                            server_side=False,
                            server_hostname=destination[0]
                        )
                        log_event("Security", "[SECURE_SESSION] TLS handshake completed using TLSWrapper")
                    except Exception as e:
                        log_error(ErrorCode.NETWORK_ERROR, f"[SECURE_SESSION] TLS wrapping failed: {str(e)}")
                        raise
            
            except Exception as e:
                log_error(ErrorCode.NETWORK_ERROR, f"[SECURE_SESSION] Failed to create/connect socket: {str(e)}")
                log_error(ErrorCode.NETWORK_ERROR, f"[SECURE_SESSION] Exception type: {type(e)}")
                raise
            
            # Set connected flag and update state
            log_event("Session", "[SECURE_SESSION] Updating connection state to connected")
            self._connected = True
            log_event("Session", "[SECURE_SESSION] Setting initial connection state")
            
            log_event("State", "[SECURE_SESSION] Preparing state update")
            state_update = {
                'connection_active': True,
                'last_activity': time.time()
            }
            log_event("State", f"[SECURE_SESSION] State update prepared: {state_update}")
            
            self._update_state(state_update)
            log_event("Session", "[SECURE_SESSION] Connection state updated successfully")
            
            # Generate key pair using KeyManagement
            try:
                log_event("Security", "[SECURE_SESSION] Starting key pair generation")
                if not self.key_manager.has_key_pair():
                    self.key_manager.generate_key_pair()
                    log_event("Security", "[SECURE_SESSION] Generated new key pair")
                
                # Get the public key PEM for sending to server
                public_key_pem = self.key_manager.get_public_key_pem()
                log_event("Security", f"[SECURE_SESSION] Public key size: {len(public_key_pem)} bytes")
                
            except Exception as e:
                log_error(ErrorCode.CRYPTO_ERROR, f"[SECURE_SESSION] Key generation/loading failed: {str(e)}")
                log_error(ErrorCode.CRYPTO_ERROR, f"[SECURE_SESSION] Exception type: {type(e)}")
                raise
            
            # Perform key exchange
            try:
                log_event("Security", "[SECURE_SESSION] Starting key exchange process")
                log_event("Security", "[SECURE_SESSION] Preparing key exchange message")
                
                # Generate nonce
                log_event("Security", "[SECURE_SESSION] Generating nonce for key exchange")
                nonce = self.nonce_manager.generate_nonce()
                log_event("Security", f"[SECURE_SESSION] Generated nonce: {nonce[:8]}...")
                
                # Get current timestamp
                timestamp = int(time.time())
                log_event("Security", f"[SECURE_SESSION] Using timestamp: {timestamp}")
                
                # Prepare message with temporary client ID
                temp_client_id = str(id(self))  # Temporary ID until we get server-assigned one
                key_exchange_message = {
                    'type': MessageType.KEY_EXCHANGE.value,
                    'nonce': nonce,
                    'timestamp': timestamp,
                    'client_id': temp_client_id,
                    'public_key': public_key_pem.decode('utf-8')
                }
                log_event("Security", "[SECURE_SESSION] Key exchange message prepared")
                
                # Send key exchange request
                message_bytes = json.dumps(key_exchange_message).encode('utf-8')
                log_event("Security", f"[SECURE_SESSION] Message size: {len(message_bytes)} bytes")
                sendData(self.socket, message_bytes)
                log_event("Security", "[SECURE_SESSION] Key exchange request sent successfully")
                
                # Handle server response
                response_data = receiveData(self.socket)
                log_event("Security", f"[SECURE_SESSION] Received response: {len(response_data)} bytes")
                
                response = json.loads(response_data.decode('utf-8'))
                if response.get('type') != MessageType.KEY_EXCHANGE_RESPONSE.value:
                    log_error(ErrorCode.KEY_EXCHANGE_ERROR, f"[SECURE_SESSION] Invalid response type: {response.get('type')}")
                    raise SecurityError("Invalid response type during key exchange")
                
                # Get server-assigned client ID
                self.client_id = response.get('client_id')
                if not self.client_id:
                    log_error(ErrorCode.KEY_EXCHANGE_ERROR, "[SECURE_SESSION] No client ID in server response")
                    raise SecurityError("Missing client ID in server response")
                log_event("Security", f"[SECURE_SESSION] Using server-assigned client ID: {self.client_id}")
                
                # Load server's public key and derive session key
                server_public_key = serialization.load_pem_public_key(
                    response['public_key'].encode('utf-8'),
                    backend=default_backend()
                )
                log_event("Security", "[SECURE_SESSION] Server public key loaded")
                
                private_key = self.key_manager.get_private_key()
                session_key = Crypto.derive_session_key(
                    peer_public_key=server_public_key,
                    private_key=private_key,
                    context=b'session key'
                )
                log_event("Security", "[SECURE_SESSION] Session key derived successfully")
                
                # Store session key using server-assigned client ID
                self.key_manager.store_session_key(self.client_id, session_key)
                log_event("Security", "[SECURE_SESSION] Session key stored successfully")
                
                
                # Start monitoring
                log_event("Connection", "[SECURE_SESSION] Starting connection monitoring threads")
                self.start_connection_monitoring()
                log_event("Connection", "[SECURE_SESSION] Connection monitoring started successfully")
                
                # Update session state
                log_event("State", "[SECURE_SESSION] Updating final session state")
                self._update_state({
                    'session_established': True,
                    'key_exchange_complete': True
                })
                log_event("Session", "[SECURE_SESSION] Session state updated - secure session established")
                
                log_event("Session", "[SECURE_SESSION] Secure session establishment completed successfully")
                return True
                
            except Exception as e:
                log_error(ErrorCode.KEY_EXCHANGE_ERROR, f"[SECURE_SESSION] Key exchange failed: {str(e)}")
                raise
                
        except Exception as e:
            log_error(ErrorCode.CONNECTION_ERROR, f"[SECURE_SESSION] Failed to establish secure session: {str(e)}")
            log_error(ErrorCode.CONNECTION_ERROR, f"[SECURE_SESSION] Exception type: {type(e)}")
            self._cleanup_connection()
            return False

    def _secure_clear_bytes(self, data: bytes):
        """Securely clear sensitive bytes from memory."""
        if data:
            # Overwrite with random data
            random_data = os.urandom(len(data))
            data_view = memoryview(data).cast('B')
            random_view = memoryview(random_data).cast('B')
            data_view[:] = random_view
            # Overwrite with zeros
            data_view[:] = b'\x00' * len(data)
            del data_view
            del random_view

    def send_message(self, message: str) -> bool:
        """Send an encrypted message to the server."""
        try:
            # Convert message to bytes
            message_bytes = message.encode('utf-8')
            
            # Get session key with server-assigned client ID
            session_key = self.key_manager.get_session_key(self.client_id)
            if not session_key:
                raise SecurityError("No session key available")
            
            # Get sequence number first
            sequence = self.sequence_manager.get_next_sequence()
            
            # Create associated data for authentication - only include stable fields
            aad_dict = {
                'sender_id': self.client_id,
                'sequence': sequence
            }
            associated_data = json.dumps(aad_dict, sort_keys=True).encode('utf-8')
            
            # Get current timestamp for message metadata
            timestamp = int(time.time())
            
            # Encrypt the message with associated data
            ciphertext, nonce, tag = Crypto.encrypt(
                data=message_bytes,
                key=session_key,
                associated_data=associated_data
            )
            
            # Get signing key and create signature
            signing_key = self.key_manager.get_signing_key()
            signature = Crypto.sign(ciphertext, signing_key)
            
            # Package the message - use same values as AAD
            message_data = {
                'type': MessageType.DATA.value,
                'encryptedMessage': ciphertext.hex(),
                'nonce': nonce.hex(),
                'tag': tag.hex(),
                'version': 1,
                'timestamp': timestamp,
                'sender_id': aad_dict['sender_id'],
                'sequence': aad_dict['sequence'],
                'signature': signature.hex()
            }
            
            # Send the message
            message_bytes = json.dumps(message_data).encode('utf-8')
            sendData(self.socket, message_bytes)
            
            # Wait for acknowledgment with timeout
            try:
                self.socket.settimeout(5)  # 5 second timeout for ack
                ack_data = receiveData(self.socket)
                if ack_data:
                    ack_message = parseMessage(ack_data)
                    if ack_message.get('type') == MessageType.ACKNOWLEDGE.value:
                        # Decrypt and log acknowledgment
                        ciphertext = bytes.fromhex(ack_message['encryptedMessage'])
                        nonce = bytes.fromhex(ack_message['nonce'])
                        tag = bytes.fromhex(ack_message['tag'])
                        
                        decrypted_ack = Crypto.decrypt(
                            ciphertext=ciphertext,
                            key=session_key,
                            nonce=nonce,
                            tag=tag
                        )
                        log_event("Communication", f"CLIENT RECEIVED ACK Received server acknowledgment: {decrypted_ack.decode('utf-8')}")
            except socket.timeout:
                log_event("Communication", "No acknowledgment received within timeout")
            finally:
                self.socket.settimeout(self._connection_timeout)  # Restore original timeout
            
            return True
            
        except Exception as e:
            log_error(ErrorCode.COMMUNICATION_ERROR, f"Failed to send message: {e}")
            return False


    def handle_key_renewal_request(self):
        """Handle key renewal with state synchronization."""
        with self._state_lock:
            try:
                if not self.is_connected():
                    raise RuntimeError("Not connected to server")

                # Generate new keys
                new_session_key, new_public_key = self.key_manager.handle_key_renewal_request(
                    self._secure_storage.retrieve('server_public_key')
                )
                
                # Store new keys temporarily
                self._secure_storage.store('temp_session_key', new_session_key)
                self._secure_storage.store('temp_public_key', new_public_key)
                
                try:
                    # Send renewal request
                    self._send_key_renewal_request(new_public_key)
                    
                    # Wait for and verify server response
                    if not self.handle_key_renewal_response():
                        raise RuntimeError("Failed to complete key renewal")
                    
                    # Commit new keys
                    self._commit_key_renewal()
                    log_event("Key Renewal", "Key renewal completed successfully")
                    
                except Exception as e:
                    # Cleanup temporary keys on failure
                    self._secure_storage.remove('temp_session_key')
                    self._secure_storage.remove('temp_public_key')
                    raise
                    
            except Exception as e:
                log_error(ErrorCode.KEY_RENEWAL_ERROR, f"Key renewal failed: {e}")
                self.terminate_session()

    def _commit_key_renewal(self):
        """Commit new keys after successful renewal."""
        with self._state_lock:
            try:
                # Move temporary keys to active
                new_session_key = self._secure_storage.retrieve('temp_session_key')
                new_public_key = self._secure_storage.retrieve('temp_public_key')
                
                if not new_session_key or not new_public_key:
                    raise RuntimeError("Missing temporary keys")
                    
                # Store new keys
                self._secure_storage.store('session_key', new_session_key)
                self._secure_storage.store('server_public_key', new_public_key)
                
                # Clear temporary storage
                self._secure_storage.remove('temp_session_key')
                self._secure_storage.remove('temp_public_key')
                
            except Exception as e:
                log_error(ErrorCode.KEY_RENEWAL_ERROR, f"Failed to commit key renewal: {e}")
                raise

    def handle_key_renewal_response(self):
        """
        Handles the key renewal response by delegating to KeyManagement.
        """
        try:
            # Use KeyManagement to initiate key renewal
            private_key, public_key = self.key_manager.initiate_key_renewal()
            
            # Send the new public key to the server
            sendData(self.socket, public_key)
            log_event("Key Renewal", "Sent new public key to server.")

            # Receive the server's new public key
            server_new_public_pem = receiveData(self.socket)
            server_new_public_key = serialization.load_pem_public_key(
                server_new_public_pem,
                backend=default_backend()
            )
            log_event("Key Renewal", "Received new public key from server.")

            # Derive the new session key
            context = b"session key derivation"
            self.session_key = Crypto.derive_session_key(server_new_public_key, private_key, context)
            log_event("Session", "New session key derived successfully.")

            with self._lock:
                self.private_key = private_key
                self.server_public_key = server_new_public_key

        except Exception as e:
            log_event("Error", f"Handling key renewal response failed: {e}")
            self.terminate_session()  # Critical failure should terminate session

    def terminate_session(self):
        """Enhanced session termination with state and resource cleanup."""
        try:
            # Send termination message if socket is available before stopping listener
            if self.socket is not None:
                termination_message = packageMessage(
                    encryptedMessage='',
                    signature='',
                    nonce=self.nonce_manager.generate_nonce(),
                    timestamp=int(time.time()),
                    type=MessageType.SESSION_TERMINATION.value
                )
                try:
                    sendData(self.socket, termination_message)
                except Exception as e:
                    log_error(ErrorCode.NETWORK_ERROR, f"Failed to send termination message: {e}")
            
            # Now stop listening (this will close the socket)
            self.stop_listening()
            
            self._update_state({
                'connection_active': False,
                'session_established': False,
                'key_exchange_complete': False
            })
            
            # Stop all monitoring threads and cleanup resources
            self._cleanup_resources()
            
            # Clear secure storage
            with self._storage_lock:
                self._secure_storage.clear()
            
            # Reset state
            with self._state_lock:
                for key in self._state:
                    if isinstance(self._state[key], bool):
                        self._state[key] = False
                    elif isinstance(self._state[key], (int, float)):
                        self._state[key] = 0
                    else:
                        self._state[key] = 'disconnected'
                self._persist_state()
            
            self._notify_state_change(False)
            
        except Exception as e:
            log_error(ErrorCode.SESSION_ERROR, f"Session termination failed: {e}")
            raise

    def start_listening(self):
        """Start listening for server messages."""
        try:
            with self._listener_lock:
                if self._listener_thread and self._listener_thread.is_alive():
                    return  # Already listening
                
                # Reset shutdown flag and set a short timeout so our listener loop can periodically check for shutdown.
                self._shutting_down = False
                self.listening = True
                if self.socket:
                    self.socket.settimeout(1)
                self.listen_thread = threading.Thread(target=self._listen_for_messages)
                self.listen_thread.daemon = True
                self.listen_thread.start()
                
                # Wait briefly to ensure thread starts
                time.sleep(0.1)
                
                if not self.listen_thread.is_alive():
                    raise RuntimeError("Listener thread failed to start")
                    
                log_event("Communication", "Started listening for server messages")
                
        except Exception as e:
            self.listening = False
            log_error(ErrorCode.THREAD_ERROR, f"Failed to start listener: {e}")
            raise

    def stop_listening(self):
        """Stop listening for server messages."""
        try:
            # Signal the listener thread to stop
            self._shutting_down = True
            if self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except Exception as e:
                    pass
                self.socket.close()
                self.socket = None
            
            # Wait for listener thread to finish (reduced timeout)
            with self._listener_lock:
                if self.listen_thread and self.listen_thread.is_alive():
                    self.listen_thread.join(timeout=0.5)  # Reduced timeout from 2 to 0.5 seconds
                    if self.listen_thread.is_alive():
                        log_error(ErrorCode.THREAD_ERROR, "Listener thread failed to stop")
                    self.listen_thread = None
                
            log_event("Communication", "Stopped listening for server messages")
            
        except Exception as e:
            log_error(ErrorCode.THREAD_ERROR, f"Error stopping listener: {e}")

    def _listen_for_messages(self):
        """Listen for incoming messages from server."""
        retry_count = 0
        max_retries = 3
        retry_delay = 1
        connection_closed = False
        
        try:
            log_event("Communication", "Started message listener thread")
            
            while not self._shutting_down:
                try:
                    if not self.listening or not self._connected:
                        break
                        
                    if not self.socket or self.socket.fileno() == -1:
                        log_event("Communication", "Socket invalid, stopping listener")
                        break

                    data = receiveData(self.socket)
                    if data is None:
                        if not self.listening:
                            break
                        if not connection_closed:  # Only log once
                            log_event("Communication", "No data received, connection may be closed")
                            connection_closed = True
                        if retry_count >= max_retries:
                            break
                        retry_count += 1
                        time.sleep(retry_delay)
                        continue
                    
                    connection_closed = False  # Reset flag on successful receive
                    retry_count = 0
                    
                    self.process_server_message(data)
                    self._update_activity_timestamp()
                    
                except socket.timeout:
                    continue
                except socket.error as e:
                    if self._shutting_down or not self.listening:  # Do not log errors during shutdown
                        break
                    if not connection_closed:  # Only log once
                        log_error(ErrorCode.NETWORK_ERROR, f"Socket error during receive: {e}")
                        connection_closed = True
                    break
                except Exception as e:
                    if not self.listening:
                        break
                    log_error(ErrorCode.NETWORK_ERROR, f"Error receiving message: {e}")
                    break
                    
        finally:
            self._connected = False
            self.listening = False
            log_event("Communication", "Message listener thread stopped")


    def process_server_message(self, data: bytes):
        """Process received server message."""
        try:
            # First try to decode as JSON for basic messaging
            try:
                message_data = json.loads(data.decode('utf-8'))
                
                # Handle basic message type
                if isinstance(message_data, dict) and message_data.get('type') == 'response':
                    log_event("Communication", f"Received server response: {message_data['content']}")
                    return
                    
            except json.JSONDecodeError:
                # Not a JSON message, try parsing as a secure message
                pass
                
            # Parse and validate the secure message
            message = parseMessage(data)
            
            # Validate timestamp
            timestamp = message.get('timestamp', 0)
            current_time = int(time.time())
            
            # Reject messages older than 5 minutes or future messages
            if abs(current_time - timestamp) > 300:
                log_error(ErrorCode.VALIDATION_ERROR, "Message timestamp outside acceptable range")
                return
                
            message_type = message.get('type')
            
            # Handle different message types using enum
            if message_type == MessageType.DATA.value:
                # Get session key
                session_key = self.key_manager.get_session_key(self.client_id)
                if not session_key:
                    raise SecurityError("No session key available")
                
                # Decrypt message
                ciphertext = bytes.fromhex(message['encryptedMessage'])
                nonce = bytes.fromhex(message['nonce'])
                tag = bytes.fromhex(message['tag'])
                
                decrypted_msg = Crypto.decrypt(
                    ciphertext=ciphertext,
                    key=session_key,
                    nonce=nonce,
                    tag=tag
                )
                
                print(f"\nReceived message from server: {decrypted_msg.decode('utf-8')}\n")
                
                # Send acknowledgment
                ack_content = f"Message received: {decrypted_msg[:20]}..."
                
                # Encrypt acknowledgment
                ciphertext, nonce, tag = Crypto.encrypt(
                    data=ack_content.encode('utf-8'),
                    key=session_key
                )
                
                # Package acknowledgment
                ack_message = packageMessage(
                    encryptedMessage=ciphertext.hex(),
                    signature='',
                    nonce=nonce.hex(),
                    tag=tag.hex(),
                    timestamp=int(time.time()),
                    type=MessageType.ACKNOWLEDGE.value,
                    sender_id=self.client_id
                )
                
                # Send acknowledgment
                sendData(self.socket, ack_message)
                log_event("Communication", "Sent acknowledgment to server")
                
            elif message_type == MessageType.ACKNOWLEDGE.value:
                # Get session key
                session_key = self.key_manager.get_session_key(self.client_id)
                if not session_key:
                    raise SecurityError("No session key available")
                
                # Decrypt acknowledgment
                ciphertext = bytes.fromhex(message['encryptedMessage'])
                nonce = bytes.fromhex(message['nonce'])
                tag = bytes.fromhex(message['tag'])
                
                decrypted_ack = Crypto.decrypt(
                    ciphertext=ciphertext,
                    key=session_key,
                    nonce=nonce,
                    tag=tag
                )
                
                log_event("Communication", f"CLIENT RECEIVED ACK Received server acknowledgment: {decrypted_ack.decode('utf-8')}")
                
            elif message_type == MessageType.KEY_RENEWAL_REQUEST.value:
                self.handle_key_renewal_request()
                
            elif message_type == MessageType.SESSION_TERMINATION.value:
                self.terminate_session()
                
            elif message_type == MessageType.ERROR.value:
                error_msg = message.get('encryptedMessage', 'Unknown error')
                log_error(ErrorCode.SERVER_ERROR, f"Error from server: {error_msg}")
                
            else:
                log_error(ErrorCode.VALIDATION_ERROR, f"Unknown message type: {message_type}")
                
        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Error processing message: {e}")


    def _secure_clear_memory(self, *objects):
        """Securely clear sensitive objects from memory."""
        for obj in objects:
            if isinstance(obj, bytes):
                self._secure_clear_bytes(obj)
            elif isinstance(obj, dict):
                for value in obj.values():
                    self._secure_clear_memory(value)
            elif isinstance(obj, (list, tuple, set)):
                for item in obj:
                    self._secure_clear_memory(item)

    def start_connection_monitoring(self):
        """Start connection monitoring threads."""
        try:
            # Start heartbeat thread
            self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
            self._heartbeat_thread.daemon = True
            self._heartbeat_thread.start()
            self._track_resource('thread', self._heartbeat_thread)

            # Start cleanup thread
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop)
            self._cleanup_thread.daemon = True
            self._cleanup_thread.start()
            self._track_resource('thread', self._cleanup_thread)
            
            log_event("Connection", "Connection monitoring started")
            
        except Exception as e:
            log_error(ErrorCode.THREAD_ERROR, f"Failed to start monitoring threads: {e}")
            raise

    def _update_activity_timestamp(self):
        """Update the last activity timestamp."""
        try:
            # Store as string representation of float
            timestamp = str(time.time())
            self._secure_storage.store('last_activity', timestamp.encode('utf-8'))
        except Exception as e:
            log_error(ErrorCode.STATE_ERROR, f"Failed to update activity timestamp: {e}")

    def _heartbeat_loop(self):
        """Send periodic heartbeats to keep connection alive."""
        while self.is_connected():
            try:
                if not self._connected:
                    break
                    
                # Instead of sleeping for the full heartbeat interval at once,
                # sleep in small increments to check for a shutdown signal.
                heartbeat_interval = self._heartbeat_interval
                interval_increment = 0.5  # seconds
                elapsed = 0.0
                while elapsed < heartbeat_interval:
                    if self._shutting_down:
                        break
                    time.sleep(interval_increment)
                    elapsed += interval_increment
                if self._shutting_down:
                    break
                    
                # Check connection state before sending
                if not self.is_connected() or not self._connected:
                    break
                    
                with self._send_lock:
                    try:
                        # Create proper heartbeat message with all required fields
                        heartbeat_message = packageMessage(
                            encryptedMessage='',  # Empty but included
                            signature='',
                            nonce=self.nonce_manager.generate_nonce(),
                            timestamp=int(time.time()),
                            type=MessageType.KEEPALIVE.value,
                            sequence=self.sequence_manager.get_next_sequence(),
                            sender_id=self.client_id
                        )
                        sendData(self.socket, heartbeat_message)
                        self._update_activity_timestamp()
                        log_event("Connection", "Heartbeat sent successfully")
                    except Exception as e:
                        log_error(ErrorCode.NETWORK_ERROR, f"Failed to send heartbeat: {e}")
                        self._handle_connection_failure()
                        break
                    
            except Exception as e:
                log_error(ErrorCode.NETWORK_ERROR, f"Heartbeat failed: {e}")
                self._handle_connection_failure()
                break

    def _cleanup_loop(self):
        """Periodically check and cleanup stale connection state."""
        while not self._shutting_down:
            total_interval = self._cleanup_interval
            interval_increment = 1  # seconds
            elapsed = 0.0
            while not self._shutting_down and elapsed < total_interval:
                time.sleep(interval_increment)
                elapsed += interval_increment
            if self._shutting_down:
                break
            try:
                self._check_connection_state()
            except Exception as e:
                log_error(ErrorCode.GENERAL_ERROR, f"Cleanup loop error: {e}")

    def _check_connection_state(self):
        """Check connection state and cleanup if stale."""
        with self._state_lock:
            if not self.is_connected():
                return

            current_time = time.time()
            last_activity_bytes = self._secure_storage.retrieve('last_activity')
            # Convert bytes to float
            last_activity = float(last_activity_bytes.decode('utf-8')) if last_activity_bytes else 0

            if current_time - last_activity > self._activity_timeout:
                log_error(ErrorCode.CONNECTION_ERROR, "Connection inactive, terminating")
                self.terminate_session()
                return

            # Verify socket is still valid
            try:
                # Try to read with zero length to check connection
                self.socket.settimeout(1)
                self.socket.recv(0)
            except socket.timeout:
                # Timeout is okay - connection is still alive
                pass
            except Exception:
                # Other errors indicate connection issues
                log_error(ErrorCode.CONNECTION_ERROR, "Socket verification failed")
                self.terminate_session()

    def _update_state(self, state_updates: dict):
        """Update client state in a thread-safe manner."""
        with self._state_lock:
            # Define valid state keys
            valid_keys = {
                'connected',
                'session_established',
                'key_exchange_complete',
                'last_activity',
                'connection_active',  # Use this instead of connection_state
                'last_server_sequence',
                'messages_received',
                'last_key_renewal'
            }
            
            log_event("State", f"[CLIENT] Updating state with keys: {list(state_updates.keys())}")
            
            # Validate and update state
            for key, value in state_updates.items():
                if key in valid_keys:
                    self._state[key] = value
                    log_event("State", f"[CLIENT] Updated state key '{key}' to {value}")
                else:
                    log_error(ErrorCode.STATE_ERROR, 
                             f"[CLIENT] Invalid state key: {key}")
                
            self._persist_state()
            log_event("State", "[CLIENT] State persisted successfully")

    def _cleanup_connection(self):
        """Clean up connection resources."""
        try:
            if hasattr(self, 'socket') and self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except Exception:
                    pass
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.socket = None
                
            self._connected = False  # Ensure connected flag is cleared
            
            # Update state using dictionary format
            self._update_state({
                'connection_active': False,
                'session_established': False,
                'key_exchange_complete': False
            })
            
            # Clear session key
            with self._storage_lock:
                self._secure_storage.remove('session_key')
                
            log_event("Connection", "[CLIENT] Cleaning up connection state")
            self._update_state({
                'connection_active': False,
                'session_established': False,
                'key_exchange_complete': False
            })
            log_event("Connection", "[CLIENT] Connection state cleaned up")
        except Exception as e:
            log_error(ErrorCode.RESOURCE_ERROR, f"Error during connection cleanup: {e}")


    def _track_resource(self, resource_type: str, resource):
        """Track resource allocation."""
        with self._resource_lock:
            if resource_type == 'thread':
                self._resources['threads'].add(resource)
            elif resource_type == 'temp_file':
                self._resources['temp_files'].add(resource)
            elif resource_type == 'key_material':
                self._resources['key_material'].add(resource)
            elif resource_type == 'buffer':
                self._resources['buffers'].append(resource)
            elif resource_type == 'socket':
                self._resources['socket'] = resource

    def _release_resource(self, resource_type: str, resource):
        """Release tracked resource."""
        with self._resource_lock:
            try:
                if resource_type == 'thread':
                    self._resources['threads'].remove(resource)
                elif resource_type == 'temp_file':
                    self._resources['temp_files'].remove(resource)
                    if os.path.exists(resource):
                        os.remove(resource)
                elif resource_type == 'key_material':
                    self._resources['key_material'].remove(resource)
                    self._secure_clear_memory(resource)
                elif resource_type == 'buffer':
                    self._resources['buffers'].remove(resource)
                    self._secure_clear_memory(resource)
                elif resource_type == 'socket':
                    if self._resources['socket'] == resource:
                        self._resources['socket'] = None
            except Exception as e:
                log_error(ErrorCode.RESOURCE_ERROR, f"Failed to release resource: {e}")

    def _cleanup_resources(self):
        """Comprehensive resource cleanup."""
        with self._resource_lock:
            # Clean up threads
            for thread in list(self._resources['threads']):
                try:
                    if thread.is_alive():
                        thread.join(timeout=5)
                    self._release_resource('thread', thread)
                except Exception as e:
                    log_error(ErrorCode.RESOURCE_ERROR, f"Thread cleanup failed: {e}")

            # Clean up temporary files
            for file_path in list(self._resources['temp_files']):
                self._release_resource('temp_file', file_path)

            # Clean up key material
            for key_material in list(self._resources['key_material']):
                self._release_resource('key_material', key_material)

            # Clean up buffers
            for buffer in list(self._resources['buffers']):
                self._release_resource('buffer', buffer)

            # Clean up socket
            if self._resources['socket']:
                try:
                    self._resources['socket'].close()
                except Exception:
                    pass
                self._resources['socket'] = None

    def _persist_state(self):
        """Persist current state to secure storage."""
        try:
            with self._state_lock:
                # Convert state to JSON-serializable format
                serializable_state = {}
                for key, value in self._state.items():
                    if isinstance(value, (str, int, float, bool, list, dict)):
                        serializable_state[key] = value
                    else:
                        # Convert non-serializable types to string representation
                        serializable_state[key] = str(value)
                
                # Convert to bytes before storing
                state_bytes = json.dumps(serializable_state).encode('utf-8')
                self._secure_storage.store('client_state', state_bytes)
                log_event("State", "Client state persisted successfully")
                
        except Exception as e:
            log_error(ErrorCode.STATE_ERROR, f"Failed to persist state: {e}")

    def _cleanup_base(self):
        """Base cleanup for socket and resources."""
        try:
            log_event("Cleanup", "[CLEANUP] Starting base cleanup")
            
            # Close socket if it exists
            if hasattr(self, 'socket') and self.socket:
                try:
                    if self.socket.fileno() != -1:
                        try:
                            self.socket.shutdown(socket.SHUT_RDWR)
                        except:
                            pass
                        self.socket.close()
                except:
                    pass
                self.socket = None
                
            # Clean up resources
            with self._resource_lock:
                # Clean up buffers
                for buffer in list(self._resources['buffers']):
                    self._release_resource('buffer', buffer)
                    
                # Clean up temporary files
                for file_path in list(self._resources['temp_files']):
                    self._release_resource('temp_file', file_path)
                    
                # Clean up key material
                for key_material in list(self._resources['key_material']):
                    self._release_resource('key_material', key_material)
                    
                # Reset socket resource
                self._resources['socket'] = None
                
            log_event("Cleanup", "[CLEANUP] Base cleanup completed")
            
        except Exception as e:
            log_error(ErrorCode.CLEANUP_ERROR, f"Base cleanup failed: {e}")

    def _cleanup_session(self):
        """Clean up session resources."""
        try:
            # Stop listening first
            self.stop_listening()
            
            # Clear secure storage with timeout
            try:
                if hasattr(self, '_secure_storage'):
                    self._secure_storage.clear()
            except Exception as e:
                log_error(ErrorCode.CLEANUP_ERROR, f"Error clearing secure storage: {e}")
            
            # Reset session state
            try:
                self._reset_session_state()
            except Exception as e:
                log_error(ErrorCode.CLEANUP_ERROR, f"Error resetting session state: {e}")
            
        except Exception as e:
            log_error(ErrorCode.CLEANUP_ERROR, f"Error during session cleanup: {e}")

    def shutdown(self):
        """Shutdown the client and cleanup all resources."""
        try:
            log_event("Cleanup", "[CLEANUP] Starting full shutdown")
            
            # Set shutdown flag
            self._shutting_down = True
            
            # Call terminate_session to send termination message and perform cleanup
            try:
                self.terminate_session()
            except Exception as e:
                log_error(ErrorCode.SESSION_ERROR, f"Session termination failed during shutdown: {e}")
            
            # Join the listener thread if running (reduced timeout)
            if self.listen_thread is not None and self.listen_thread.is_alive():
                self.listen_thread.join(timeout=0.5)  # Reduced timeout from 2 to 0.5 seconds
            
            # Optionally, if additional thread resources are stored in self._resources, iterate and join them.
            if hasattr(self, '_resources'):
                threads = self._resources.get('thread', [])
                for thread in threads:
                    if isinstance(thread, threading.Thread) and thread.is_alive():
                        thread.join(timeout=0.5)  # Reduced timeout
            
            # Now perform base cleanup
            try:
                self._cleanup_base()
            except Exception as e:
                log_error(ErrorCode.CLEANUP_ERROR, f"Base cleanup failed: {e}")
            
        except Exception as e:
            log_error(ErrorCode.SHUTDOWN_ERROR, f"Error during shutdown: {e}")

    def _handle_connection_failure(self):
        """Handle connection failures with cleanup and recovery."""
        try:
            log_event("Connection", "[CONNECTION] Handling connection failure")
            
            # Perform session cleanup
            self._cleanup_session()
            
            # Attempt reconnection if configured
            if hasattr(self, 'max_retries') and self.max_retries > 0:
                if self._attempt_reconnection():
                    log_event("Connection", "[CONNECTION] Reconnection successful")
                    return
                
            log_event("Connection", "[CONNECTION] Connection failure handled")
            
        except Exception as e:
            log_error(ErrorCode.CONNECTION_ERROR, f"Connection failure handling failed: {e}")

    def _reset_session_state(self):
        """Reset all session-related state."""
        try:
            # Update connection state
            with self._state_lock:
                self._connected = False
                state_updates = {
                    'connection_active': False,
                    'session_established': False,
                    'key_exchange_complete': False,
                    'last_activity': time.time()
                }
                self._update_state(state_updates)
                log_event("State", f"Reset session state: {list(state_updates.keys())}")
                
            # Reset managers
            try:
                if hasattr(self, 'key_manager'):
                    if hasattr(self, '_secure_storage'):
                        keys_to_remove = [k for k in self._secure_storage._storage.keys() 
                                        if k.startswith('session_key_')]
                        for key in keys_to_remove:
                            self._secure_storage.remove(key)
                            
                if hasattr(self, 'sequence_manager'):
                    self.sequence_manager.reset()
                if hasattr(self, 'nonce_manager'):
                    self.nonce_manager.cleanup_old_nonces()
                log_event("State", "Reset all managers")
            except Exception as e:
                log_error(ErrorCode.CLEANUP_ERROR, f"Manager cleanup failed: {e}")
            
            # Notify about state change
            self._notify_state_change(False)
            
        except Exception as e:
            log_error(ErrorCode.CLEANUP_ERROR, f"Failed to reset session state: {e}")

