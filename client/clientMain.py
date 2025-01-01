import threading
import socket
import json
import os
from typing import Optional, Tuple
from datetime import datetime
import time
from contextlib import contextmanager

# Cryptography imports
from cryptography.hazmat.primitives import serialization, padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID, AuthorityInformationAccessOID

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
from security.TLSWrapper import TLSWrapper
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

    def __init__(self):
        """Initialize the client with secure defaults."""
        self._lock = threading.Lock()
        self._connection_timeout = 30
        self._message_timeout = 300
        self._max_message_size = 1024 * 1024
        self._secure_storage = SecureStorage()  # Centralized secure storage
        self._state_lock = threading.Lock()
        self._send_lock = threading.Lock()
        self._key_lock = threading.Lock()
        self._storage_lock = threading.Lock()
        self._handler_lock = threading.Lock()
        self._activity_lock = threading.Lock()
        
        # Initialize managers
        self.key_manager = KeyManagement()
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
        self._heartbeat_interval = 60  # 1 minute
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
        
        # State management
        self._state = {
            'connection_state': 'disconnected',  # disconnected, connecting, connected, terminating
            'session_established': False,
            'key_exchange_complete': False,
            'certificate_verified': False,
            'last_server_sequence': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'last_key_renewal': 0,
            'encryption_failures': 0,
            'reconnection_attempts': 0
        }
        self._state_lock = threading.RLock()  # Reentrant lock for state operations
        
        # Resource tracking
        self._resources = {
            'socket': None,
            'threads': set(),
            'temp_files': set(),
            'key_material': set(),
            'buffers': []
        }
        self._resource_lock = threading.Lock()

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
        """Thread-safe session key storage."""
        with self._key_lock:
            with self._storage_lock:
                self._secure_storage.store('session_key', {
                    'key': key,
                    'created_at': time.time(),
                    'last_used': time.time(),
                    'encryption_failures': 0
                })
            log_event("Session", "Session key updated")
            self._notify_state_change(True)

    def get_session_key(self) -> Optional[bytes]:
        """Thread-safe session key retrieval."""
        with self._key_lock:
            with self._storage_lock:
                key_data = self._secure_storage.retrieve('session_key')
                if key_data:
                    key_data['last_used'] = time.time()
                    self._secure_storage.store('session_key', key_data)
                    return key_data['key']
                return None

    def is_connected(self) -> bool:
        """Check if client has active connection with activity tracking."""
        with self._state_lock:
            key_data = self._secure_storage.retrieve('session_key')
            last_activity = self._secure_storage.retrieve('last_activity') or 0
            current_time = time.time()

            return (self._connected and 
                    self.socket is not None and 
                    key_data is not None and
                    current_time - key_data['created_at'] < 3600 and  # 1 hour max key age
                    current_time - last_activity < self._activity_timeout)  # Check activity timeout

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

    def establish_secure_session(self, destination: Tuple[str, int]) -> bool:
        """Establish secure session with proper timeout handling."""
        try:
            # Connect with timeout
            self._perform_with_timeout(
                self._connect_to_server,
                'connect',
                destination
            )
            
            # Perform TLS handshake with timeout
            self._perform_with_timeout(
                self._perform_tls_handshake,
                'handshake'
            )
            
            # Perform key exchange with timeout
            self._perform_with_timeout(
                self._perform_key_exchange,
                'key_exchange'
            )
            
            # Verify server identity with timeout
            self._perform_with_timeout(
                self._verify_server_identity,
                'verification'
            )
            
            return True
            
        except Exception as e:
            log_error(ErrorCode.SESSION_ERROR, f"Session establishment failed: {e}")
            self.terminate_session()
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
                # Clear secure storage
                self._secure_storage.clear()
                
                # Close socket
                if self.socket:
                    try:
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
                
            except Exception as e:
                log_error(ErrorCode.CLEANUP_ERROR, f"Resource cleanup failed: {e}")

    def send_message(self, message: str) -> bool:
        """Send message with timeout handling."""
        return self._perform_with_timeout(
            self._send_message_internal,
            'send',
            message
        )

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
                message = self._perform_with_timeout(
                    self._receive_message_internal,
                    'receive'
                )
                if message:
                    self.process_server_message(message)
            except socket.timeout:
                continue
            except Exception as e:
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
            self._update_state(connection_state='terminating')
            
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
        """
        Starts a background thread to listen for incoming messages.
        """
        if self.listening:
            log_event("Error", "Already listening for messages.")
            return

        self.listening = True
        self.listen_thread = threading.Thread(target=self.receive_messages)
        self.listen_thread.daemon = True
        self.listen_thread.start()
        log_event("Listening", "Started listening for incoming messages.")

    def stop_listening(self):
        """
        Stops listening for incoming messages.
        """
        if not self.listening:
            log_event("Error", "Not currently listening.")
            return

        self.listening = False
        if self.listen_thread:
            self.listen_thread.join()
        log_event("Listening", "Stopped listening for incoming messages.")

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

    def process_server_message(self, message_data: dict):
        """Thread-safe message processing with error propagation."""
        try:
            with self._activity_lock:
                self._update_activity_timestamp()
            
            if not self._validate_message(message_data):
                error_msg = "Message validation failed"
                self._notify_error(ErrorCode.VALIDATION_ERROR, error_msg)
                return

            if not self.is_connected():
                error_msg = "Not connected to server"
                self._notify_error(ErrorCode.STATE_ERROR, error_msg)
                return
            
            message_type = message_data.get('type')
            
            # Verify signature before processing any message
            if not self._verify_message_signature(message_data):
                error_msg = "Invalid message signature"
                self._notify_error(ErrorCode.SECURITY_ERROR, error_msg)
                return
            
            if message_type == MessageType.ACKNOWLEDGE.value:
                log_event("Message", "Server acknowledged message receipt")
                
            elif message_type == MessageType.SERVER_RESPONSE.value:
                self._handle_server_response(message_data)
                
            elif message_type == MessageType.ERROR.value:
                self._handle_error_response(message_data)
                
            elif message_type == MessageType.KEY_RENEWAL_RESPONSE.value:
                self._handle_key_renewal_response(message_data)
                
            elif message_type == MessageType.SESSION_TERMINATION.value:
                log_event("Connection", "Received session termination from server")
                self.terminate_session()
                
            else:
                error_msg = f"Unknown message type: {message_type}"
                self._notify_error(ErrorCode.VALIDATION_ERROR, error_msg)
                
        except Exception as e:
            error_msg = f"Error processing server message: {e}"
            self._notify_error(ErrorCode.GENERAL_ERROR, error_msg)
            self._check_connection_state()
            raise

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
        # Start heartbeat thread
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop)
        self._heartbeat_thread.daemon = True
        self._heartbeat_thread.start()

        # Start cleanup thread
        self._cleanup_thread = threading.Thread(target=self._cleanup_loop)
        self._cleanup_thread.daemon = True
        self._cleanup_thread.start()

    def _update_activity_timestamp(self):
        """Thread-safe activity timestamp update."""
        with self._activity_lock:
            self._last_activity = time.time()
            with self._storage_lock:
                self._secure_storage.store('last_activity', self._last_activity)

    def _heartbeat_loop(self):
        """Send periodic heartbeats to keep connection alive."""
        while self.is_connected():
            try:
                time.sleep(self._heartbeat_interval)
                self._send_heartbeat()
            except Exception as e:
                log_error(ErrorCode.NETWORK_ERROR, f"Heartbeat failed: {e}")

    def _send_heartbeat(self):
        """Send heartbeat message to server."""
        try:
            heartbeat_message = packageMessage(
                encryptedMessage='',
                signature='',
                nonce=self.nonce_manager.generate_nonce(),
                timestamp=int(time.time()),
                type=MessageType.HEARTBEAT.value
            )
            with self._send_lock:
                sendData(self.socket, heartbeat_message)
            self._update_activity_timestamp()
        except Exception as e:
            log_error(ErrorCode.NETWORK_ERROR, f"Failed to send heartbeat: {e}")
            self._check_connection_state()

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
            last_activity = self._secure_storage.retrieve('last_activity') or 0

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

    def _update_state(self, **kwargs):
        """Thread-safe state update with validation."""
        with self._state_lock:
            for key, value in kwargs.items():
                if key not in self._state:
                    log_error(ErrorCode.STATE_ERROR, f"Invalid state key: {key}")
                    continue
                self._state[key] = value
                log_event("State", f"State updated: {key}={value}")
            self._persist_state()

    def _persist_state(self):
        """Persist current state to secure storage."""
        with self._state_lock:
            with self._storage_lock:
                self._secure_storage.store('client_state', self._state)

    def _restore_state(self):
        """Restore state from secure storage."""
        with self._state_lock:
            with self._storage_lock:
                stored_state = self._secure_storage.retrieve('client_state')
                if stored_state:
                    self._state.update(stored_state)

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
