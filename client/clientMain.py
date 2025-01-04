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

@contextmanager
def socket_timeout_context(sock, timeout):
    """Context manager for socket timeout operations."""
    original_timeout = sock.gettimeout()
    try:
        sock.settimeout(timeout)
        yield
    finally:
        sock.settimeout(original_timeout)

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
        self._resource_lock = threading.Lock()
        
        # Generate keys if needed
        if not self.key_manager.has_key_pair():
            self.key_manager.generate_key_pair()

    def register_error_handler(self, handler):
        """Register callback for error notifications."""
        with self._handler_lock:
            self._error_handlers.append(handler)
            
    def register_state_change_handler(self, handler):
        """Register callback for connection state changes."""
        with self._handler_lock:
            self._state_change_handlers.append(handler)
            
    def _notify_error(self, error_code: ErrorCode, error_message: str):
        """Notify all registered error handlers."""
        with self._handler_lock:
            for handler in self._error_handlers:
                try:
                    handler(error_code, error_message)
                except Exception as e:
                    log_error(ErrorCode.CALLBACK_ERROR, f"Error handler failed: {e}")

    def _notify_state_change(self, new_state: bool):
        """Notify all registered state change handlers."""
        with self._handler_lock:
            for handler in self._state_change_handlers:
                try:
                    handler(new_state)
                except Exception as e:
                    log_error(ErrorCode.CALLBACK_ERROR, f"State change handler failed: {e}")

    def set_session_key(self, key: bytes):
        """Store the session key securely."""
        try:
            log_event("Security", "[SECURE_SESSION] Storing session key")
            with self._storage_lock:
                # Convert the data to bytes using JSON
                key_data = json.dumps({
                    'key': key.hex(),  # Convert bytes to hex string
                    'timestamp': int(time.time())
                }).encode('utf-8')
                self._secure_storage.store('session_key', key_data)
            log_event("Security", "[SECURE_SESSION] Session key stored successfully")
        except Exception as e:
            log_error(ErrorCode.KEY_MANAGEMENT_ERROR, f"[SECURE_SESSION] Failed to store session key: {str(e)}")
            raise

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

    def _perform_with_timeout(self, operation, timeout_key, *args, **kwargs):
        """Execute operation with timeout and retry logic."""
        timeout = self._operation_timeouts.get(timeout_key, 30)
        retries = 0
        last_error = None
        
        while retries < self._retry_config['max_retries']:
            try:
                with socket_timeout_context(self.socket, timeout):
                    return operation(*args, **kwargs)
            except socket.timeout:
                delay = min(
                    self._retry_config['backoff_factor'] * (2 ** retries),
                    self._retry_config['max_delay']
                )
                log_error(
                    ErrorCode.TIMEOUT_ERROR,
                    f"{timeout_key} operation timed out, retrying in {delay}s"
                )
                time.sleep(delay)
                retries += 1
                last_error = f"{timeout_key} operation timed out"
            except Exception as e:
                log_error(ErrorCode.GENERAL_ERROR, f"{timeout_key} operation failed: {e}")
                raise
        
        raise TimeoutError(f"Operation failed after {retries} retries: {last_error}")

    def _connect_to_server(self, destination: Tuple[str, int]):
        """Establish initial TCP connection to server."""
        try:
            log_event("Connection", f"Attempting to connect to {destination[0]}:{destination[1]}")
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(self._operation_timeouts['connect'])  # Set timeout directly
            self.socket.connect(destination)
            log_event("Connection", "TCP connection established successfully")
            return True
        except Exception as e:
            log_error(ErrorCode.CONNECTION_ERROR, f"Failed to connect to server: {e}")
            return False

    def _perform_key_exchange(self):
        """Perform basic key exchange for non-TLS connections."""
        try:
            log_event("Session", "Performing basic key exchange")
            # For non-TLS connections, we'll use a simplified session key
            session_key = os.urandom(32)  # Generate a 256-bit session key
            self.key_manager.set_session_key('default', session_key)
            return True
        except Exception as e:
            log_error(ErrorCode.KEY_EXCHANGE_ERROR, f"Key exchange failed: {e}")
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
                    log_event("Security", "[SECURE_SESSION] Wrapping socket with TLS")
                    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                    
                    # Load certificates
                    context.load_cert_chain(
                        certfile=str(self.tls_config.cert_path),
                        keyfile=str(self.tls_config.key_path)
                    )
                    context.load_verify_locations(cafile=str(self.tls_config.ca_path))
                    
                    if self.tls_config.verify_mode == "CERT_REQUIRED":
                        context.verify_mode = ssl.CERT_REQUIRED
                        context.check_hostname = True
                    
                    # Wrap the socket
                    self.socket = context.wrap_socket(
                        self.socket,
                        server_hostname=destination[0]
                    )
                    log_event("Security", "[SECURE_SESSION] TLS handshake completed")
                
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
                # Add debug log for session key
                log_event("Security", f"[DEBUG] Client session key (hex): {session_key.hex()}")
                
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

    def _cleanup_session_resources(self, resources_acquired: bool):
        """Comprehensive cleanup of session resources."""
        with self._state_lock:
            try:
                # Stop listening first
                self.stop_listening()
                
                # Set flags to stop all monitoring threads
                self.running = False
                self.listening = False
                
                # Clear secure storage
                self._secure_storage.clear()
                
                # Close socket
                if self.socket:
                    try:
                        # Only shutdown if socket is still connected
                        if self.is_connected():
                            self.socket.shutdown(socket.SHUT_RDWR)
                    except Exception:
                        pass
                    try:
                        self.socket.close()
                    except Exception:
                        pass
                    self.socket = None
                    
                # Reset state
                self._connected = False
                self.sequence_manager.reset()
                self.nonce_manager.cleanup_old_nonces()
                
                # Wait for monitoring threads to finish
                if self.listen_thread and self.listen_thread.is_alive():
                    self.listen_thread.join(timeout=2)
                if hasattr(self, 'heartbeat_thread') and self.heartbeat_thread and self.heartbeat_thread.is_alive():
                    self.heartbeat_thread.join(timeout=2)
                
            except Exception as e:
                log_error(ErrorCode.CLEANUP_ERROR, f"Resource cleanup failed: {e}")

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

    def _handle_encryption_failure(self):
        """Thread-safe encryption failure handling with error propagation."""
        try:
            with self._key_lock:
                with self._storage_lock:
                    key_data = self._secure_storage.retrieve('session_key')
                    if not key_data:
                        error_msg = "No active session key"
                        self._notify_error(ErrorCode.SECURITY_ERROR, error_msg)
                        self.terminate_session()
                        raise SecurityError(error_msg)

                    # Update failure count
                    key_data['encryption_failures'] += 1
                    self._secure_storage.store('session_key', key_data)

                    if key_data['encryption_failures'] >= self.max_encryption_failures:
                        error_msg = "Maximum encryption failures exceeded"
                        self._notify_error(ErrorCode.SECURITY_ERROR, error_msg)
                        self.terminate_session()
                        raise SecurityError(error_msg)
                    else:
                        # Attempt key renewal
                        self._initiate_key_renewal()

        except Exception as e:
            error_msg = f"Encryption failure handling error: {e}"
            self._notify_error(ErrorCode.ENCRYPTION_ERROR, error_msg)
            self.terminate_session()
            raise

    def _handle_send_failure(self):
        """Handle send operation failure with state recovery."""
        with self._state_lock:
            try:
                # Attempt to verify connection
                self.socket.settimeout(5)
                self.socket.send(b'')
            except Exception:
                # Connection is dead, initiate recovery
                self._initiate_recovery()

    def _initiate_recovery(self):
        """Attempt to recover from connection failure."""
        with self._state_lock:
            try:
                # Save current state
                old_session_key = self._secure_storage.retrieve('session_key')
                old_server_key = self._secure_storage.retrieve('server_public_key')
                
                # Attempt reconnection
                if self._attempt_reconnection():
                    # Verify recovered state
                    if not self._verify_session_state():
                        # State verification failed, terminate and cleanup
                        self.terminate_session()
                        raise RuntimeError("Failed to verify recovered session state")
                else:
                    # Reconnection failed, terminate session
                    self.terminate_session()
                    raise RuntimeError("Failed to recover connection")
                    
            finally:
                # Clear old keys
                if old_session_key:
                    self._secure_clear_bytes(old_session_key)
                if old_server_key:
                    self._secure_clear_bytes(old_server_key)

    def receive_messages(self):
        """Receive messages with timeout handling."""
        while self.listening:
            try:
                # Receive raw data from socket
                data = receiveData(self.socket)
                if data:
                    # Process the received message
                    self.process_server_message(data)
                    # Update activity timestamp
                    self._update_activity_timestamp()
            except socket.timeout:
                continue
            except Exception as e:
                if self.listening:  # Only log if we're still meant to be listening
                    log_error(ErrorCode.NETWORK_ERROR, f"Receive error: {e}")
                    self._check_connection_state()

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
                    if not self._handle_renewal_response():
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
            # Should add a termination message to server before cleanup
            termination_message = packageMessage(
                encryptedMessage='',
                signature='',
                nonce=self.nonce_manager.generate_nonce(),
                timestamp=int(time.time()),
                type=MessageType.SESSION_TERMINATION.value
            )
            sendData(self.socket, termination_message)  # Add this
            
            self._update_state({
                'connection_active': False,
                'session_established': False,
                'key_exchange_complete': False
            })
            
            # Stop all monitoring threads
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
        self.listening = True
        self.listen_thread = threading.Thread(target=self._listen_loop)
        self.listen_thread.daemon = True
        self.listen_thread.start()
        log_event("Communication", "Started listening for server messages")

    def stop_listening(self):
        """Stop listening for server messages."""
        self.listening = False
        if self.listen_thread:
            self.listen_thread.join(timeout=2)
        log_event("Communication", "Stopped listening for server messages")

    def _listen_loop(self):
        """Listen for incoming server messages."""
        while self.listening and self.is_connected():
            try:
                data = receiveData(self.socket)
                if data:
                    # Add debug logging
                    log_event("Communication", f"Received server message: {data}")
                    self.process_server_message(data)
            except Exception as e:
                if self.listening:  # Only log if we're still meant to be listening
                    log_error(ErrorCode.NETWORK_ERROR, f"Error receiving server message: {e}")

    def _validate_server_certificate_and_identity(self, hostname: str) -> None:
        """
        Comprehensively validate server certificate and identity.
        
        Args:
            hostname (str): Expected server hostname
            
        Raises:
            ValueError: If certificate validation fails
            SecurityError: If identity verification fails
        """
        if not self.server_certificate:
            raise ValueError("No server certificate available")

        try:
            # 1. Verify certificate chain
            if not hasattr(self, 'tls_config') or not self.tls_config.ca_cert_path:
                raise ValueError("No CA certificate configured")
            
            ca_cert = self.key_manager.load_certificate(self.tls_config.ca_cert_path)
            if not self.key_manager.verify_certificate_chain(
                self.server_certificate, 
                ca_cert,
                self.tls_config.cert_chain_path
            ):
                raise ValueError("Server certificate chain verification failed")

            # 2. Verify certificate validity period
            current_time = datetime.utcnow()
            if current_time < self.server_certificate.not_valid_before:
                raise ValueError("Server certificate not yet valid")
            if current_time > self.server_certificate.not_valid_after:
                raise ValueError("Server certificate has expired")

            # 3. Verify hostname against SAN and CN
            self._verify_hostname_in_cert(hostname)

            # 4. Check certificate revocation if enabled
            if self.tls_config.check_ocsp:
                if not self.key_manager.check_certificate_revocation(
                    self.server_certificate, 
                    ca_cert
                ):
                    raise ValueError("Server certificate has been revoked")

            # 5. Verify key usage and extended key usage
            self._verify_certificate_usage()

            log_event("Security", "Server certificate and identity validated successfully")

        except Exception as e:
            log_error(ErrorCode.AUTHENTICATION_ERROR, f"Certificate validation failed: {e}")
            raise SecurityError(f"Certificate validation failed: {e}")

    def _verify_hostname_in_cert(self, hostname: str) -> None:
        """
        Verify hostname against certificate SAN and CN fields.
        
        Args:
            hostname (str): The hostname to verify
            
        Raises:
            ValueError: If hostname verification fails
        """
        try:
            # Check Subject Alternative Names (SAN)
            san_ext = self.server_certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_names = san_ext.value.get_values_for_type(x509.DNSName)
            
            if hostname in san_names:
                return
            
            # Fallback to Common Name only if no SAN extension
        except x509.ExtensionNotFound:
            common_name = self.server_certificate.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
            
            if hostname != common_name:
                raise ValueError(f"Hostname {hostname} doesn't match certificate")

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
                self._handle_key_renewal_request(message)
                
            elif message_type == MessageType.SESSION_TERMINATION.value:
                self._handle_termination_request()
                
            elif message_type == MessageType.ERROR.value:
                error_msg = message.get('encryptedMessage', 'Unknown error')
                log_error(ErrorCode.SERVER_ERROR, f"Error from server: {error_msg}")
                
            else:
                log_error(ErrorCode.VALIDATION_ERROR, f"Unknown message type: {message_type}")
                
        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Error processing message: {e}")

    def _verify_message_signature(self, message: dict) -> bool:
        """Verify message signature and integrity."""
        try:
            # Create signature payload including all critical fields
            signature_payload = {
            'encryptedMessage': message.get('encryptedMessage', ''),
            'nonce': message.get('nonce', ''),
            'timestamp': message.get('timestamp', 0),
            'type': message.get('type', ''),
            'sequence': message.get('sequence', 0),
            'sender_id': message.get('sender_id', 'server'),
            'iv': message.get('iv', ''),
            'tag': message.get('tag', '')
            }
            
            signature_bytes = json.dumps(signature_payload, sort_keys=True).encode('utf-8')
            signature = message.get('signature')
            
            if not signature:
                return False
            
            server_public_key = self._secure_storage.retrieve('server_public_key')
            if not server_public_key:
                return False
            
            return self.key_manager.verify_signature(
                server_public_key,
                signature_bytes,
                bytes.fromhex(signature)
            )
            
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"Signature verification failed: {e}")
            return False

    def _handle_server_response(self, message_data: dict):
        """Handle encrypted server response with validation."""
        try:
            # Get and validate session key
            session_key = self.get_session_key()
            if not session_key:
                raise SecurityError("No active session key")
            
            # Decrypt and validate message
            encrypted_msg = bytes.fromhex(message_data.get('encryptedMessage', ''))
            iv = bytes.fromhex(message_data.get('iv', ''))
            tag = bytes.fromhex(message_data.get('tag', ''))
            
            secure_msg = SecureMessage(
                encrypted_message=encrypted_msg,
                iv=iv,
                tag=tag
            )
                        
            decrypted_message = Crypto.decrypt(secure_msg, session_key)
            
            # Process decrypted message
            if hasattr(self, 'message_handler') and self.message_handler:
                self.message_handler(decrypted_message)
            
        except EncryptionError as e:
            self._handle_encryption_failure()
            raise
        except Exception as e:
            log_error(ErrorCode.ENCRYPTION_ERROR, f"Failed to process server response: {e}")
            raise

    def _complete_session_establishment(self, server_public_pem: bytes, private_pem: bytes) -> bool:
        """Complete the session establishment process by loading keys and deriving session key."""
        try:
            # Load server's public key
            self.server_public_key = serialization.load_pem_public_key(
                server_public_pem,
                backend=default_backend()
            )
            log_event("Key Exchange", "Server public key loaded successfully.")

            # Load client's private key
            self.private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            log_event("Key Management", "Client private key loaded successfully.")

            # Derive session key
            context = b"session key derivation"
            self.session_key = Crypto.derive_session_key(
                self.server_public_key,
                self.private_key,
                context
            )
            log_event("Session", "Session key derived successfully.")
            return True

        except Exception as e:
            log_error(ErrorCode.KEY_MANAGEMENT_ERROR, f"Failed to complete session establishment: {e}")
            return False

    def _receive_with_timeout(self, size: int, timeout: int) -> Optional[bytes]:
        """
        Receive data from socket with timeout and validation.
        
        Args:
            size (int): Maximum size of data to receive
            timeout (int): Timeout in seconds
            
        Returns:
            Optional[bytes]: Received data or None if no data received
        """
        try:
            self.socket.settimeout(timeout)
            data = self.socket.recv(size)
            if not data:
                log_error(ErrorCode.NETWORK_ERROR, "Connection closed by peer")
                return None
            return data
        except socket.timeout:
            log_error(ErrorCode.NETWORK_ERROR, "Timeout while receiving data")
            return None
        except Exception as e:
            log_error(ErrorCode.NETWORK_ERROR, f"Error receiving data: {e}")
            return None
        finally:
            self.socket.settimeout(self.connection_timeout)  # Restore original timeout

    def _validate_message(self, message: dict) -> bool:
        """Comprehensive message validation."""
        try:
            # Validate basic message structure
            if not isinstance(message, dict):
                log_error(ErrorCode.VALIDATION_ERROR, "Invalid message format")
                return False
            
            # Validate timestamp
            timestamp = message.get('timestamp', 0)
            current_time = int(time.time())
            if abs(current_time - timestamp) > self._message_timeout:
                log_error(ErrorCode.VALIDATION_ERROR, "Message timestamp outside acceptable range")
                return False
            
            # Validate sequence number
            sequence = message.get('sequence')
            sender_id = message.get('sender_id', 'server')
            if not self.sequence_manager.validate_sequence(sequence, sender_id):
                log_error(ErrorCode.VALIDATION_ERROR, "Invalid message sequence")
                return False

            # Validate nonce
            nonce = message.get('nonce')
            if not self.nonce_manager.validate_nonce(nonce):
                log_error(ErrorCode.VALIDATION_ERROR, "Invalid or reused nonce")
                return False

            # Validate message type
            message_type = message.get('type')
            if not message_type or not isinstance(message_type, str):
                log_error(ErrorCode.VALIDATION_ERROR, "Invalid message type")
                return False
            
            # Validate message size
            if len(str(message)) > self._max_message_size:
                log_error(ErrorCode.VALIDATION_ERROR, "Message exceeds maximum size")
                return False

            return True
            
        except Exception as e:
            log_error(ErrorCode.VALIDATION_ERROR, f"Message validation failed: {e}")
            return False

    def _verify_server_key_exchange(self, server_public_pem: bytes) -> bool:
        """
        Verify server's public key during key exchange.
        
        Args:
            server_public_pem (bytes): Server's public key in PEM format
            
        Returns:
            bool: True if verification succeeds
            
        Raises:
            SecurityError: If key verification fails
        """
        try:
            # 1. Verify key format and size
            server_public_key = serialization.load_pem_public_key(
                server_public_pem,
                backend=default_backend()
            )
            
            # 2. Verify key belongs to certificate
            cert_public_key = self.server_certificate.public_key()
            if server_public_key.public_numbers() != cert_public_key.public_numbers():
                raise SecurityError("Server's public key doesn't match certificate")
            
            # 3. Generate and send challenge
            challenge = os.urandom(32)
            encrypted_challenge = server_public_key.encrypt(
                challenge,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Send challenge
            self.socket.sendall(encrypted_challenge)
            
            # Receive and verify response
            response = self._receive_complete_message(1024)
            if response != challenge:
                raise SecurityError("Server failed to prove key ownership")
            
            return True
            
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"Server key verification failed: {e}")
            raise SecurityError(f"Server key verification failed: {e}")

    def _receive_complete_message(self, max_size: int, timeout: int = 30) -> bytes:
        """
        Receive a complete message with size prefix.
        
        Args:
            max_size (int): Maximum allowed message size
            timeout (int): Receive timeout in seconds
            
        Returns:
            bytes: Complete message
            
        Raises:
            ValueError: If message size exceeds limit
            TimeoutError: If receive times out
        """
        try:
            self.socket.settimeout(timeout)
            
            # Receive 4-byte size prefix
            size_data = b''
            while len(size_data) < 4:
                chunk = self.socket.recv(4 - len(size_data))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving size")
                size_data += chunk
                
            message_size = int.from_bytes(size_data, byteorder='big')
            if message_size > max_size:
                raise ValueError(f"Message size {message_size} exceeds maximum {max_size}")
                
            # Receive complete message
            message = b''
            while len(message) < message_size:
                chunk = self.socket.recv(min(4096, message_size - len(message)))
                if not chunk:
                    raise ConnectionError("Connection closed while receiving message")
                message += chunk
                
            return message
            
        except socket.timeout:
            raise TimeoutError("Receive operation timed out")
        finally:
            self.socket.settimeout(self.connection_timeout)

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
                    
                time.sleep(self._heartbeat_interval)
                
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
        while True:
            try:
                time.sleep(self._cleanup_interval)
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

    def _verify_state_consistency(self) -> bool:
        """Verify state consistency with server."""
        try:
            # Send state verification request
            state_info = {
                'messages_received': self._state['messages_received'],
                'last_sequence': self._state['last_server_sequence'],
                'last_key_renewal': self._state['last_key_renewal']
            }
            
            verification_message = packageMessage(
                encryptedMessage=json.dumps(state_info),
                signature='',
                nonce=self.nonce_manager.generate_nonce(),
                timestamp=int(time.time()),
                type=MessageType.STATE_VERIFICATION.value
            )
            
            response = self._perform_with_timeout(
                lambda: self._send_and_receive_verification(verification_message),
                'verification'
            )
            
            if not response or not self._validate_state_response(response):
                raise StateError("State verification failed")
            
            return True
            
        except Exception as e:
            log_error(ErrorCode.STATE_ERROR, f"State verification failed: {e}")
            return False

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

    def _perform_tls_handshake(self):
        """Perform TLS handshake with server."""
        try:
            log_event("Security", "Starting TLS handshake")
            
            # Create TLS context
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            
            # Configure TLS settings
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            
            # Load certificates if provided
            if hasattr(self, 'tls_config') and self.tls_config:
                if self.tls_config.cert_path:
                    context.load_cert_chain(
                        certfile=str(self.tls_config.cert_path),
                        keyfile=str(self.tls_config.key_path)
                    )
                if self.tls_config.ca_path:
                    context.load_verify_locations(cafile=str(self.tls_config.ca_path))
            
            # Wrap socket with TLS
            hostname = self.destination[0] if hasattr(self, 'destination') else None
            self.socket = context.wrap_socket(
                self.socket,
                server_hostname=hostname
            )
            
            log_event("Security", "TLS handshake completed successfully")
            return True
            
        except ssl.SSLError as e:
            log_error(ErrorCode.SECURITY_ERROR, f"TLS handshake failed: {e}")
            return False
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"TLS setup failed: {e}")
            return False

    def _sign_message(self, message_data: dict) -> str:
        """Sign message data using the client's signing key."""
        try:
            # Create signature payload with relevant fields
            signature_payload = {
                'sequence': message_data.get('sequence'),
                'encryptedMessage': message_data.get('encryptedMessage'),
                'nonce': message_data.get('nonce'),
                'timestamp': message_data.get('timestamp'),
                'type': message_data.get('type')
            }
            
            # Convert to bytes in a consistent format
            signature_bytes = json.dumps(signature_payload, sort_keys=True).encode('utf-8')
            
            # Get signing key from key manager and use Crypto to sign
            signing_key = self.key_manager.get_signing_key()
            signature = Crypto.sign(data=signature_bytes, private_key=signing_key)
            return signature.hex()
            
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"Failed to sign message: {e}")
            raise

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

    def _handle_key_exchange_response(self, response: dict) -> bool:
        """Handle key exchange response from server."""
        try:
            # Extract server's public key and client ID
            server_public_key_pem = response.get('public_key')
            self.client_id = response.get('client_id')  # Store server-assigned ID
            
            if not server_public_key_pem or not self.client_id:
                log_error(ErrorCode.KEY_EXCHANGE_ERROR, "Missing public key or client ID in response")
                return False
            
            log_event("Security", f"[SECURE_SESSION] Using server-assigned client ID: {self.client_id}")
            
            # Load server's public key
            server_public_key = serialization.load_pem_public_key(
                server_public_key_pem.encode('utf-8'),
                backend=default_backend()
            )
            
            # Get private key and derive session key
            log_event("Security", "[SECURE_SESSION] Getting private key and deriving session key")
            private_key = self.key_manager.get_private_key()
            
            # Derive shared key
            session_key = Crypto.derive_session_key(
                peer_public_key=server_public_key,
                private_key=private_key,
                context=b'session key'
            )
            
            # Store session key using server-assigned client ID
            self.key_manager.store_session_key(self.client_id, session_key)
            log_event("Security", "[SECURE_SESSION] Session key stored successfully")
            # Add debug log for session key
            log_event("Security", f"[DEBUG] Client session key (hex): {session_key.hex()}")
            
            return True
            
        except Exception as e:
            log_error(ErrorCode.KEY_EXCHANGE_ERROR, f"Key exchange response handling failed: {e}")
            return False

    def cleanup(self):
        """Clean up client resources."""
        try:
            if hasattr(self, 'socket') and self.socket:
                try:
                    self.socket.shutdown(socket.SHUT_RDWR)
                except:
                    pass
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
                
            log_event("Client", "Cleanup completed successfully")
        except Exception as e:
            log_error(ErrorCode.CLEANUP_ERROR, f"Error during cleanup: {e}")

    def shutdown(self):
        """Graceful shutdown with proper cleanup."""
        try:
            # Set flags first to stop threads
            self.running = False
            self._connected = False
            self.listening = False
            
            # Send termination message if still connected
            if self.socket and self.socket.fileno() != -1:
                try:
                    termination_message = packageMessage(
                        encryptedMessage='',
                        signature='',
                        nonce=self.nonce_manager.generate_nonce(),
                        timestamp=int(time.time()),
                        type=MessageType.SESSION_TERMINATION.value
                    )
                    sendData(self.socket, termination_message)
                except:
                    pass
            
            # Wait for threads to finish
            if hasattr(self, '_heartbeat_thread') and self._heartbeat_thread:
                self._heartbeat_thread.join(timeout=2)
            if hasattr(self, 'listen_thread') and self.listen_thread:
                self.listen_thread.join(timeout=2)
            
            # Then cleanup resources
            self.terminate_session()
            
        except Exception as e:
            log_error(ErrorCode.CLEANUP_ERROR, f"Error during shutdown: {e}")

    def _attempt_reconnection(self) -> bool:
        """Attempt to reconnect to the server."""
        try:
            for attempt in range(self.max_retries):
                log_event("Connection", f"Reconnection attempt {attempt + 1}/{self.max_retries}")
                try:
                    # Create new socket
                    self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    self.socket.settimeout(self._connection_timeout)
                    self.socket.connect(self.destination)
                    
                    # Re-establish secure session
                    if self._establish_secure_session():
                        return True
                    
                except Exception as e:
                    log_error(ErrorCode.NETWORK_ERROR, f"Reconnection attempt failed: {e}")
                    time.sleep(self.retry_delay * (attempt + 1))
                
            return False
            
        except Exception as e:
            log_error(ErrorCode.NETWORK_ERROR, f"Reconnection failed: {e}")
            return False

    def _handle_connection_failure(self):
        """Handle connection failures gracefully."""
        try:
            with self._state_lock:
                self._connected = False
                self._update_state({
                    'connection_active': False,
                    'session_established': False,
                    'key_exchange_complete': False,
                    'last_activity': time.time()  # Update last activity
                })
                
                # Try to close socket gracefully
                if self.socket:
                    try:
                        self.socket.shutdown(socket.SHUT_RDWR)
                    except:
                        pass
                    try:
                        self.socket.close()
                    except:
                        pass
                    self.socket = None
                
                # Notify about connection failure
                self._notify_state_change(False)
                
        except Exception as e:
            log_error(ErrorCode.CONNECTION_ERROR, f"Error handling connection failure: {e}")

