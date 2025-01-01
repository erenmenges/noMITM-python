import threading
import socket
import json
import time
import os
from typing import Dict, Optional, Tuple
from datetime import datetime

# Cryptography imports
from cryptography.hazmat.primitives import serialization, hashes
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
    CryptoConstants,
    EncryptionError,
    DecryptionError
)
from KeyManagement import KeyManagement
from Utils import (
    NonceManager, 
    log_event, 
    log_error, 
    ErrorCode, 
    SequenceManager,
    SecurityError,
    StateError,
    CommunicationError,
    TimeoutError
)
from security.TLSWrapper import TLSWrapper
from security.secure_storage import SecureStorage
from config.security_config import TLSConfig

class Server:
    def __init__(self, host: str, port: int, tls_config=None):
        self.host = host
        self.port = port
        # Initialize with default values
        self.tls_config = tls_config or TLSConfig(enabled=False)  # Default to disabled TLS
        self._lock = threading.Lock()
        self._clients_lock = threading.Lock()
        self.clients: Dict[str, dict] = {}
        self.running = False
        self.server_socket = None
        self.key_manager = KeyManagement()
        self.nonce_manager = NonceManager()
        self.sequence_manager = SequenceManager()
        self.certificate = None
        self.private_key = None
        self.ca_certificate = None
        self.connection_timeout = 30
        self.message_handler = None
        self.max_retries = 3
        self.retry_delay = 1
        self._initialized = False  # Track initialization state
        self._secure_storage = SecureStorage()  # Add secure storage
        
        # Initialize certificates if TLS is enabled
        if self.tls_config.enabled:
            self._initialize_certificates()
        
        self._initialized = True

    def _initialize_certificates(self):
        """Initialize server certificates and validation chain."""
        try:
            # Load server certificate and private key
            self.certificate = self.key_manager.load_certificate(
                self.tls_config.cert_config.cert_path
            )
            self.private_key = self.key_manager.load_private_key(
                self.tls_config.cert_config.key_path
            )
            
            # Load CA certificate for client validation
            self.ca_certificate = self.key_manager.load_certificate(
                self.tls_config.cert_config.ca_cert_path
            )
            
            log_event("Security", "Server certificates initialized successfully")
            
        except Exception as e:
            log_error(ErrorCode.AUTHENTICATION_ERROR, f"Failed to initialize certificates: {e}")
            raise

    def start(self):
        """Start the server and listen for connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # If TLS is enabled, wrap the server socket
            if self.tls_config and self.tls_config.enabled:
                tls_wrapper = TLSWrapper(self.tls_config)
                self.server_socket = tls_wrapper.wrap_socket(
                    self.server_socket,
                    server_side=True
                )
            
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            log_event("Server", f"Server started on {self.host}:{self.port}")
            
            while self.running:
                client_socket, address = self.server_socket.accept()
                self._handle_new_connection(client_socket, address)
                
        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Server failed to start: {e}")
            self.stop()
            raise

    def _handle_new_connection(self, client_socket: socket.socket, address: tuple):
        """Handle new client connection with certificate validation."""
        try:
            if self.tls_config and self.tls_config.enabled:
                # Validate client certificate if mutual TLS is enabled
                if self.tls_config.cert_config.require_client_cert:
                    client_cert = self._validate_client_certificate(client_socket)
                    if not client_cert:
                        client_socket.close()
                        return
                    
            # Generate client ID and store connection
            client_id = self._generate_client_id(address)
            with self._clients_lock:
                self.clients[client_id] = {
                    'connection': client_socket,
                    'address': address,
                    'last_activity': time.time(),
                    'certificate': client_cert if self.tls_config and self.tls_config.cert_config.require_client_cert else None
                }
            
            # Start client handler thread
            client_thread = threading.Thread(
                target=self._handle_client,
                args=(client_id,)
            )
            client_thread.daemon = True
            client_thread.start()
            
            log_event("Connection", f"New client connected from {address}")
            
        except Exception as e:
            log_error(ErrorCode.AUTHENTICATION_ERROR, f"Failed to handle new connection: {e}")
            client_socket.close()

    def _validate_client_certificate(self, client_socket: socket.socket) -> Optional[x509.Certificate]:
        """Validate client certificate and perform security checks."""
        try:
            cert_binary = client_socket.getpeercert(binary_form=True)
            if not cert_binary:
                raise ValueError("No client certificate provided")
            
            client_cert = x509.load_der_x509_certificate(cert_binary, default_backend())
            
            # Verify certificate chain
            if not self.key_manager.verify_certificate(client_cert, self.ca_certificate):
                raise ValueError("Client certificate verification failed")
                
            # Check certificate revocation if enabled
            if self.tls_config.check_ocsp:
                if not self.key_manager.check_certificate_revocation(client_cert, self.ca_certificate):
                    raise ValueError("Client certificate has been revoked")
                    
            # Validate allowed subjects if configured
            if self.tls_config.cert_config.allowed_subjects:
                subject = client_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
                if subject not in self.tls_config.cert_config.allowed_subjects:
                    raise ValueError(f"Client subject {subject} not in allowed subjects list")
                    
            log_event("Security", f"Client certificate validated successfully")
            return client_cert
            
        except Exception as e:
            log_error(ErrorCode.AUTHENTICATION_ERROR, f"Client certificate validation failed: {e}")
            return None

    def _generate_client_id(self, address: tuple) -> str:
        """Generate unique client ID."""
        return f"{address[0]}:{address[1]}_{time.time()}"

    def cleanup_inactive_clients(self):
        """Remove inactive client connections."""
        current_time = time.time()
        inactive_clients = []
        
        with self._clients_lock:  # Add thread safety
            for client_id, client_data in self.clients.items():
                if current_time - client_data['last_activity'] > self.connection_timeout:
                    inactive_clients.append(client_id)
                    
            for client_id in inactive_clients:
                self.close_client_connection(client_id)

    def close_client_connection(self, client_id: str):
        """Safely close client connection with proper key cleanup."""
        with self._clients_lock:
            if client_id not in self.clients:
                return
                
            # Securely clear session key
            self._secure_storage.remove(f'session_key_{client_id}')
            
            # Proceed with normal cleanup
            try:
                client_data = self.clients[client_id]
                conn = client_data['connection']
                
                # Send termination message and close connection
                try:
                    termination_message = packageMessage(
                        encryptedMessage='',
                        signature='',
                        nonce=self.nonce_manager.generate_nonce(),
                        timestamp=int(time.time()),
                        type=MessageType.SESSION_TERMINATION.value
                    )
                    sendData(conn, termination_message)
                except Exception:
                    pass
                
                # Close socket
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except socket.error:
                    pass
                finally:
                    try:
                        conn.close()
                    except socket.error:
                        pass

                del self.clients[client_id]
                log_event("Connection", f"Client {client_id} disconnected and cleaned up")
                
            except Exception as e:
                log_error(ErrorCode.NETWORK_ERROR, f"Error during client cleanup: {e}")

    def shutdown(self):
        """Shutdown the server and cleanup all resources."""
        self.running = False
        
        # Close all client connections
        client_ids = list(self.clients.keys())  # Create a copy of keys
        for client_id in client_ids:
            try:
                # Send termination message to clients
                client_data = self.clients[client_id]
                conn = client_data['connection']
                termination_message = packageMessage(
                    encryptedMessage='',
                    signature='',
                    nonce=self.nonce_manager.generate_nonce(),
                    timestamp=int(time.time()),
                    type=MessageType.SESSION_TERMINATION
                )
                try:
                    sendData(conn, termination_message)
                except Exception:
                    pass  # Continue cleanup even if sending fails
                
                # Close connection
                self.close_client_connection(client_id)
                
            except Exception as e:
                log_error(ErrorCode.NETWORK_ERROR, f"Error during client cleanup: {e}")

        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                self.server_socket.close()
            except Exception:
                pass
            self.server_socket = None

        # Clear all internal state
        self.clients.clear()
        self.key_manager.clear_session_keys()
        self.nonce_manager.cleanup_old_nonces()
        
        log_event("Server", "Server shutdown complete")

    def handle_client(self, conn, addr, client_id):
        """Handle client connection with proper resource management."""
        client_data = None
        try:
            conn.settimeout(self.connection_timeout)
            
            # Initialize client session atomically
            with self._clients_lock:
                if client_id in self.clients:
                    # Store old connection data for cleanup
                    old_client = self.clients[client_id]
                    # Update with new connection
                    client_data = {
                        'connection': conn,
                        'address': addr,
                        'last_activity': time.time(),
                        'session_established': False,
                        'recv_buffer': bytearray(),
                        'send_buffer': bytearray()
                    }
                    self.clients[client_id] = client_data
                    
                    # Clean up old connection outside the lock
                    try:
                        old_client['connection'].shutdown(socket.SHUT_RDWR)
                        old_client['connection'].close()
                    except Exception:
                        pass
                else:
                    client_data = {
                        'connection': conn,
                        'address': addr,
                        'last_activity': time.time(),
                        'session_established': False,
                        'recv_buffer': bytearray(),
                        'send_buffer': bytearray()
                    }
                    self.clients[client_id] = client_data
            
            while self.running:
                try:
                    data = receiveData(conn)
                    if not data:
                        break
                    
                    # Update last activity timestamp
                    with self._clients_lock:
                        if client_id in self.clients:
                            self.clients[client_id]['last_activity'] = time.time()
                        else:
                            break
                    
                    # Process message
                    self.process_client_message(data, client_id)
                    
                except socket.timeout:
                    # Check for client timeout
                    with self._clients_lock:
                        if client_id in self.clients:
                            last_activity = self.clients[client_id]['last_activity']
                            if time.time() - last_activity > self.connection_timeout:
                                log_event("Connection", f"Client {client_id} timed out")
                                break
                    continue
                except ConnectionError:
                    break
                except Exception as e:
                    log_error(ErrorCode.GENERAL_ERROR, f"Error handling client message: {e}")
                    break
        finally:
            # Ensure cleanup happens
            with self._clients_lock:
                if client_id in self.clients:
                    self.close_client_connection(client_id)

    def process_client_message(self, data: str, client_id: str):
        """Process incoming client messages and handle different message types."""
        try:
            # Parse and validate the message once
            message = parseMessage(data)
            
            if not self.is_connected(client_id):
                log_error(ErrorCode.STATE_ERROR, f"Client {client_id} not connected")
                return

            # Validate timestamp
            timestamp = message.get('timestamp', 0)
            current_time = int(time.time())
            
            # Reject messages older than 5 minutes or future messages
            if abs(current_time - timestamp) > 300:
                log_error(ErrorCode.VALIDATION_ERROR, "Message timestamp outside acceptable range")
                return
            
            # Validate sequence number
            sequence = message.get('sequence')
            if not self.sequence_manager.validate_sequence(sequence, message.get('sender_id')):
                log_error(ErrorCode.VALIDATION_ERROR, "Invalid message sequence")
                return

            message_type = message.get('type')
            
            # Handle different message types using enum
            if message_type == MessageType.DATA.value:
                self._handle_data_message(client_id, message)
                
            elif message_type == MessageType.ACKNOWLEDGE.value:
                # Handle client acknowledgments
                log_event("Message", f"Received acknowledgment from client {client_id}")
                
            elif message_type == MessageType.KEY_RENEWAL_REQUEST.value:
                self.handle_key_renewal_request(client_id, message)
                
            elif message_type == MessageType.KEY_RENEWAL_RESPONSE.value:
                # Handle client's response to key renewal
                self._handle_key_renewal_response(client_id, message)
                
            elif message_type == MessageType.SESSION_TERMINATION.value:
                self._handle_termination_request(client_id)
                
            elif message_type == MessageType.ERROR.value:
                # Handle client error messages
                error_msg = message.get('encryptedMessage', 'Unknown error')
                log_error(ErrorCode.CLIENT_ERROR, f"Error from client {client_id}: {error_msg}")
                
            else:
                log_error(ErrorCode.VALIDATION_ERROR, f"Unknown message type: {message_type}")
                self._send_error_response(
                    self.clients[client_id]['connection'],
                    "Unknown message type"
                )
                
        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Error processing client message: {e}")
            try:
                with self._clients_lock:
                    if client_id in self.clients:
                        self._send_error_response(self.clients[client_id]['connection'], str(e))
            except Exception:
                pass

    def _handle_data_message(self, client_id: str, message: dict):
        """Handle data message type."""
        try:
            with self._clients_lock:
                client_data = self.clients[client_id]
                conn = client_data['connection']
                session_key = client_data.get('session_key')

            if not session_key:
                raise ValueError("No active session key")

            # Decrypt message
            secure_msg = SecureMessage.from_dict(message)
            decrypted_message = Crypto.decrypt(secure_msg, session_key)
            
            log_event("Message", f"Received message from client {client_id}")
            
            # Send acknowledgment
            ack_message = packageMessage(
                encryptedMessage='',
                signature='',
                nonce=self.nonce_manager.generate_nonce(),
                timestamp=int(time.time()),
                type=MessageType.ACKNOWLEDGE.value
            )
            sendData(conn, ack_message)
            
            # Send response
            self.send_response_message(client_id, f"Server received: {decrypted_message}")
            
        except (ValueError, DecryptionError) as e:
            log_error(ErrorCode.ENCRYPTION_ERROR, f"Failed to process encrypted message: {e}")
            self._handle_encryption_failure(client_id)
        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Error handling data message: {e}")
            self._send_error_response(conn, "Failed to process message")

    def _send_error_response(self, conn: socket.socket, error_message: str):
        """Send error response to client."""
        try:
            error_response = packageMessage(
                encryptedMessage=error_message,
                signature='',
                nonce=self.nonce_manager.generate_nonce(),
                timestamp=int(time.time()),
                type=MessageType.ERROR.value
            )
            sendData(conn, error_response)
        except Exception as e:
            log_error(ErrorCode.NETWORK_ERROR, f"Failed to send error response: {e}")

    def send_response_message(self, client_id: str, message: str):
        """Send an encrypted response message to a client with retry mechanism."""
        retries = 0
        last_error = None
        
        while retries < self.max_retries:
            try:
                with self._clients_lock:
                    if client_id not in self.clients:
                        log_error(ErrorCode.VALIDATION_ERROR, f"Unknown client ID: {client_id}")
                        return
                    client_data = self.clients[client_id]
                    conn = client_data['connection']
                    session_key = client_data.get('session_key')

                if not session_key or len(session_key) != CryptoConstants.AES_KEY_SIZE:
                    log_error(ErrorCode.ENCRYPTION_ERROR, 
                             f"Invalid session key length. Expected {CryptoConstants.AES_KEY_SIZE} bytes")
                    return

                # Encrypt and package message
                iv, ciphertext, tag = Crypto.aes_encrypt(message.encode('utf-8'), session_key)
                response = packageMessage(
                    encryptedMessage=ciphertext.hex(),
                    signature='',
                    nonce=self.nonce_manager.generate_nonce(),
                    timestamp=int(time.time()),
                    type=MessageType.SERVER_RESPONSE.value,
                    iv=iv.hex(),
                    tag=tag.hex()
                )
                
                sendData(conn, response)
                log_event("Message", f"Sent response to client {client_id}")
                return True
                
            except ConnectionError as e:
                last_error = e
                retries += 1
                if retries < self.max_retries:
                    log_event("Network", f"Retrying send operation ({retries}/{self.max_retries})")
                    time.sleep(self.retry_delay)
                continue
            except Exception as e:
                log_error(ErrorCode.NETWORK_ERROR, f"Failed to send response message: {e}")
                self._send_error_response(conn, "Internal server error")
                return False
        
        # If we've exhausted retries, close the connection
        log_error(ErrorCode.NETWORK_ERROR, f"Failed to send after {self.max_retries} attempts: {last_error}")
        self.close_client_connection(client_id)
        return False

    def set_message_handler(self, handler):
        """
        Set the message handler callback function.
        
        Args:
            handler: Callable that takes a message string as argument
        """
        if not callable(handler):
            raise ValueError("Message handler must be callable")
        with self._lock:
            self.message_handler = handler

    def _validate_message_sequence(self, message: dict, client_id: str) -> bool:
        """
        Validate both sequence number and nonce for comprehensive replay protection.
        
        Args:
            message (dict): The parsed message
            client_id (str): The client ID
        
        Returns:
            bool: True if validation passes, False otherwise
        """
        try:
            # Validate sequence number for message ordering
            sequence = message.get('sequence')
            sender_id = message.get('sender_id', client_id)
            if not self.sequence_manager.validate_sequence(sequence, sender_id):
                log_error(ErrorCode.VALIDATION_ERROR, "Invalid message sequence")
                return False

            # Validate nonce for replay protection
            nonce = message.get('nonce')
            if not self.nonce_manager.validate_nonce(nonce):
                log_error(ErrorCode.VALIDATION_ERROR, "Invalid or reused nonce")
                return False

            return True
        except Exception as e:
            log_error(ErrorCode.VALIDATION_ERROR, f"Message validation failed: {e}")
            return False

    def _verify_message_signature(self, message: dict, client_id: str) -> bool:
        """
        Verify message signature covering all critical fields.
        
        Args:
            message (dict): The message to verify
            client_id (str): The client ID
        
        Returns:
            bool: True if signature is valid
        """
        try:
            # Create signature payload including all critical fields
            signature_payload = {
                'encryptedMessage': message['encryptedMessage'],
                'nonce': message['nonce'],
                'timestamp': message['timestamp'],
                'type': message['type'],
                'sequence': message['sequence'],
                'sender_id': message.get('sender_id', client_id),
                'iv': message.get('iv', ''),
                'tag': message.get('tag', '')
            }
            
            signature_bytes = json.dumps(signature_payload, sort_keys=True).encode('utf-8')
            signature = message.get('signature')
            
            with self._clients_lock:
                if client_id not in self.clients:
                    return False
                client_public_key = self.clients[client_id].get('public_key')
                
            if not client_public_key:
                log_error(ErrorCode.SECURITY_ERROR, "No public key available for signature verification")
                return False
                
            return self.key_manager.verify_signature(
                client_public_key,
                signature_bytes,
                bytes.fromhex(signature)
            )
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"Signature verification failed: {e}")
            return False

    def handle_key_renewal_request(self, client_id: str, message: dict):
        """Handle key renewal request with verification."""
        try:
            # Verify the current request
            if not self._verify_message_signature(message, client_id):
                raise ValueError("Invalid signature on key renewal request")

            new_public_key = message.get('newPublicKey')
            if not new_public_key:
                raise ValueError("Missing new public key in renewal request")
            
            # Generate new server key pair
            server_public_pem, server_private_pem = Crypto.generate_key_pair()
            
            # Update client's session data atomically
            with self._clients_lock:
                if client_id not in self.clients:
                    raise ValueError("Client not found")
                    
                client_data = self.clients[client_id]
                old_public_key = client_data.get('public_key')
                old_session_key = client_data.get('session_key')
                
                try:
                    # Update client's public key
                    client_data['public_key'] = serialization.load_pem_public_key(
                        new_public_key.encode(),
                        backend=default_backend()
                    )
                    
                    # Derive new session key
                    new_session_key = Crypto.derive_session_key(
                        client_data['public_key'],
                        server_private_pem,
                        b"key renewal"
                    )
                    
                    # Send response with server's new public key
                    response = packageMessage(
                        encryptedMessage=server_public_pem.decode(),
                        signature='',
                        nonce=self.nonce_manager.generate_nonce(),
                        timestamp=int(time.time()),
                        type=MessageType.KEY_RENEWAL_RESPONSE.value
                    )
                    sendData(client_data['connection'], response)
                    
                    # Wait for client acknowledgment
                    ack_data = self._receive_renewal_acknowledgment(client_id)
                    if not ack_data:
                        raise ValueError("Client failed to acknowledge key renewal")
                    
                    # Verify acknowledgment with new key
                    if not self._verify_renewal_acknowledgment(ack_data, client_data['public_key']):
                        raise ValueError("Invalid key renewal acknowledgment")
                    
                    # Update session key after successful verification
                    client_data['session_key'] = new_session_key
                    self.key_manager.update_client_key(client_id, server_private_pem)
                    
                    log_event("Key Renewal", f"Completed key renewal for client {client_id}")
                    
                except Exception as e:
                    # Rollback on failure
                    client_data['public_key'] = old_public_key
                    client_data['session_key'] = old_session_key
                    raise
                    
        except Exception as e:
            log_error(ErrorCode.KEY_MANAGEMENT_ERROR, f"Key renewal failed: {e}")
            self._send_error_response(
                self.clients[client_id]['connection'],
                "Key renewal failed"
            )

    def _receive_renewal_acknowledgment(self, client_id: str, timeout: int = 30) -> Optional[dict]:
        """Wait for and receive key renewal acknowledgment."""
        try:
            with self._clients_lock:
                if client_id not in self.clients:
                    return None
                conn = self.clients[client_id]['connection']
            
            conn.settimeout(timeout)
            try:
                ack_data = receiveData(conn)
                if not ack_data:
                    return None
                
                parsed_ack = parseMessage(ack_data)
                if parsed_ack.get('type') != MessageType.KEY_RENEWAL_RESPONSE.value:
                    return None
                    
                return parsed_ack
                
            finally:
                conn.settimeout(self.connection_timeout)
                
        except Exception as e:
            log_error(ErrorCode.NETWORK_ERROR, f"Failed to receive renewal acknowledgment: {e}")
            return None

    def _verify_renewal_acknowledgment(self, ack_data: dict, public_key) -> bool:
        """Verify the key renewal acknowledgment."""
        try:
            if not ack_data.get('signature'):
                return False
                
            signature_payload = {
                'type': ack_data['type'],
                'nonce': ack_data['nonce'],
                'timestamp': ack_data['timestamp']
            }
            
            signature_bytes = json.dumps(signature_payload, sort_keys=True).encode('utf-8')
            return self.key_manager.verify_signature(
                public_key,
                signature_bytes,
                bytes.fromhex(ack_data['signature'])
            )
            
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"Failed to verify renewal acknowledgment: {e}")
            return False

    def is_connected(self, client_id: str) -> bool:
        """
        Check if a client is currently connected and has an active session.
        
        Args:
            client_id (str): The client ID to check
            
        Returns:
            bool: True if client is connected with active session
        """
        with self._clients_lock:
            if client_id not in self.clients:
                return False
            client_data = self.clients[client_id]
            return (
                client_data.get('connection') is not None and
                client_data.get('session_key') is not None and
                client_data.get('last_activity', 0) > time.time() - self.connection_timeout
            )

    def _handle_encryption_failure(self, client_id: str):
        """Handle encryption failures with proper key management."""
        try:
            with self._clients_lock:
                key_data = self._secure_storage.retrieve(f'session_key_{client_id}')
                if not key_data:
                    self.close_client_connection(client_id)
                    return

                # Update failure count
                key_data['encryption_failures'] += 1
                self._secure_storage.store(f'session_key_{client_id}', key_data)

                if key_data['encryption_failures'] >= self.max_encryption_failures:
                    log_error(ErrorCode.SECURITY_ERROR, 
                             f"Too many encryption failures for client {client_id}")
                    self.close_client_connection(client_id)
                    raise SecurityError("Maximum encryption failures exceeded")
                else:
                    self._initiate_key_renewal(client_id)

        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Error handling encryption failure: {e}")
            self.close_client_connection(client_id)
            raise

    def _handle_key_renewal_response(self, client_id: str, message: dict):
        """Handle client's response to key renewal request."""
        try:
            with self._clients_lock:
                if client_id not in self.clients:
                    return
                client_data = self.clients[client_id]
                
                # Verify the response signature
                if not self._verify_message_signature(message, client_id):
                    raise ValueError("Invalid signature on key renewal response")
                    
                # Process the new key material
                new_public_key = message.get('encryptedMessage')
                if not new_public_key:
                    raise ValueError("Missing new public key in renewal response")
                    
                # Update client's public key
                client_data['public_key'] = serialization.load_pem_public_key(
                    new_public_key.encode(),
                    backend=default_backend()
                )
                
                # Generate new session key
                new_session_key = Crypto.derive_session_key(
                    client_data['public_key'],
                    self.private_key,
                    b"key renewal"
                )
                
                # Update session key
                client_data['session_key'] = new_session_key
                
                log_event("Key Renewal", f"Completed key renewal for client {client_id}")
                
        except Exception as e:
            log_error(ErrorCode.KEY_MANAGEMENT_ERROR, f"Key renewal response handling failed: {e}")
            self.close_client_connection(client_id)

    def _store_client_session_key(self, client_id: str, key: bytes):
        """Securely store client session key with metadata."""
        with self._clients_lock:
            if client_id not in self.clients:
                return
                
            key_data = {
                'key': key,
                'created_at': time.time(),
                'last_used': time.time(),
                'encryption_failures': 0
            }
            
            # Store in secure storage
            self._secure_storage.store(f'session_key_{client_id}', key_data)
            
            # Update client record
            self.clients[client_id]['has_session_key'] = True
            log_event("Session", f"Session key updated for client {client_id}")

    def _get_client_session_key(self, client_id: str) -> Optional[bytes]:
        """Retrieve client session key with usage tracking."""
        with self._clients_lock:
            if client_id not in self.clients:
                return None
                
            key_data = self._secure_storage.retrieve(f'session_key_{client_id}')
            if key_data:
                # Update last used timestamp
                key_data['last_used'] = time.time()
                self._secure_storage.store(f'session_key_{client_id}', key_data)
                return key_data['key']
            return None
