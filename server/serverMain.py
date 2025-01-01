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
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
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
        
        # Create secure storage first
        self._secure_storage = SecureStorage()  # Add this line
        
        # Pass secure storage to KeyManagement
        self.key_manager = KeyManagement(self._secure_storage)  # Updated this line
        
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
        """Start the server with proper error handling."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            log_event("Server", f"Server started on {self.host}:{self.port}")
            
            # Start accept loop in a separate thread
            self._accept_thread = threading.Thread(target=self._accept_connections)
            self._accept_thread.daemon = True
            self._accept_thread.start()
            
        except Exception as e:
            log_error(ErrorCode.NETWORK_ERROR, f"Failed to start server: {e}")
            raise

    def _accept_connections(self):
        """Accept incoming connections with proper error handling."""
        while self.running:
            try:
                log_event("Server", "Waiting for incoming connection...")
                client_socket, address = self.server_socket.accept()
                log_event("Server", f"Accepted connection from {address[0]}:{address[1]}")
                
                # Handle client in separate thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except Exception as e:
                if self.running:  # Only log if server is still meant to be running
                    log_error(ErrorCode.NETWORK_ERROR, f"Error accepting connection: {e}")

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


    def process_client_message(self, data: bytes, client_id: str):
        """Process a message received from a client."""
        try:
            log_event("Communication", f"[PROCESS_MESSAGE] Processing message for client {client_id}")
            log_event("Communication", f"[PROCESS_MESSAGE] Raw message size: {len(data)} bytes")
            
            try:
                # Try to parse as JSON first
                message = json.loads(data.decode('utf-8'))
                log_event("Communication", f"[PROCESS_MESSAGE] Parsed JSON message: {message.get('type', 'unknown type')}")
                
                # Handle key exchange request
                if message.get('type') == MessageType.KEY_EXCHANGE.value:
                    log_event("Communication", f"[PROCESS_MESSAGE] Handling key exchange request from {client_id}")
                    self._handle_key_exchange(message, client_id)
                    return

                # For other messages, parse and validate as secure message
                log_event("Communication", f"[PROCESS_MESSAGE] Processing as secure message")
                message = parseMessage(data)
                
            except json.JSONDecodeError as e:
                log_error(ErrorCode.VALIDATION_ERROR, f"[PROCESS_MESSAGE] JSON decode error: {str(e)}")
                message = parseMessage(data)

        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"[PROCESS_MESSAGE] Error processing message: {str(e)}")
            log_error(ErrorCode.GENERAL_ERROR, f"[PROCESS_MESSAGE] Exception type: {type(e)}")

    def _handle_key_exchange(self, message: dict, client_id: str):
        """Handle key exchange request from client."""
        try:
            log_event("Security", f"[KEY_EXCHANGE] Starting key exchange handling for client {client_id}")
            
            # Log the message structure
            log_event("Security", f"[KEY_EXCHANGE] Message keys: {list(message.keys())}")
            
            # Validate basic message structure
            required_keys = ['type', 'nonce', 'timestamp', 'client_id', 'public_key']
            if not all(k in message for k in required_keys):
                missing_keys = [k for k in required_keys if k not in message]
                log_error(ErrorCode.VALIDATION_ERROR, 
                         f"[KEY_EXCHANGE] Missing required keys: {missing_keys} for client {client_id}")
                raise ValueError(f"Invalid key exchange message format. Missing: {missing_keys}")
            
            # Validate timestamp
            current_time = int(time.time())
            message_time = message['timestamp']
            time_diff = abs(current_time - message_time)
            log_event("Security", f"[KEY_EXCHANGE] Message timestamp: {message_time}, "
                                 f"Current time: {current_time}, Difference: {time_diff}s")
            
            if time_diff > 300:  # 5 minutes max difference
                log_error(ErrorCode.VALIDATION_ERROR, 
                         f"[KEY_EXCHANGE] Message too old: {time_diff}s for client {client_id}")
                raise ValueError("Key exchange message timestamp too old")
            
            # Get the session key for this client
            with self._clients_lock:
                log_event("Security", f"[KEY_EXCHANGE] Retrieving session key for client {client_id}")
                if client_id not in self.clients:
                    log_error(ErrorCode.KEY_EXCHANGE_ERROR, 
                             f"[KEY_EXCHANGE] Client {client_id} not found in clients dictionary")
                    raise ValueError(f"Client {client_id} not found")
                    
                session_key = self.clients[client_id]['session_key']
                log_event("Security", f"[KEY_EXCHANGE] Retrieved session key for client {client_id}")
                
                # Load client's public key
                log_event("Security", f"[KEY_EXCHANGE] Loading client's public key for {client_id}")
                log_event("Security", f"[KEY_EXCHANGE] Public key PEM size: {len(message['public_key'])}")
                client_public_key = serialization.load_pem_public_key(
                    message['public_key'].encode('utf-8'),
                    backend=default_backend()
                )
                log_event("Security", f"[KEY_EXCHANGE] Public key type: {type(client_public_key)}")
                log_event("Security", f"[KEY_EXCHANGE] Public key algorithms: {client_public_key.key_size}")
                
                # Generate server's ephemeral key pair
                server_private_key = ec.generate_private_key(
                    CryptoConstants.CURVE,
                    backend=default_backend()
                )
                server_public_key = server_private_key.public_key()

                # Perform ECDH to derive shared secret
                shared_key = server_private_key.exchange(
                    ec.ECDH(),
                    client_public_key
                )

                # Derive session key using HKDF
                derived_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=None,
                    info=b'session key',
                    backend=default_backend()
                ).derive(shared_key)

                # Store the derived key as session key
                self.clients[client_id]['session_key'] = derived_key

                # Send server's public key in response
                response = {
                    'type': MessageType.KEY_EXCHANGE_RESPONSE.value,
                    'nonce': self.nonce_manager.generate_nonce(),
                    'timestamp': int(time.time()),
                    'public_key': server_public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    ).decode('utf-8')
                }

                # Send response
                response_bytes = json.dumps(response).encode('utf-8')
                sendData(self.clients[client_id]['connection'], response_bytes)

                # Update client state
                self.clients[client_id]['state'] = 'key_exchanged'
                
        except Exception as e:
            log_error(ErrorCode.KEY_EXCHANGE_ERROR, 
                     f"[KEY_EXCHANGE] Key exchange failed for client {client_id}: {str(e)}")
            log_error(ErrorCode.KEY_EXCHANGE_ERROR, f"[KEY_EXCHANGE] Exception type: {type(e)}")
            
            # Send error response
            try:
                error_response = {
                    'type': MessageType.ERROR.value,
                    'error': 'Key exchange failed',
                    'nonce': self.nonce_manager.generate_nonce(),
                    'timestamp': int(time.time())
                }
                error_bytes = json.dumps(error_response).encode('utf-8')
                sendData(self.clients[client_id]['connection'], error_bytes)
            except Exception:
                pass  # Ignore errors in error handling
            
            raise

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
                'key': key.hex(),  # Convert bytes to hex string for JSON serialization
                'created_at': time.time(),
                'last_used': time.time(),
                'encryption_failures': 0
            }
            
            # Convert dict to bytes for secure storage
            key_data_bytes = json.dumps(key_data).encode('utf-8')
            self._secure_storage.store(f'session_key_{client_id}', key_data_bytes)
            
            # Update client record
            self.clients[client_id]['has_session_key'] = True
            log_event("Session", f"Session key updated for client {client_id}")

    def _get_client_session_key(self, client_id: str) -> Optional[bytes]:
        """Retrieve client session key with usage tracking."""
        with self._clients_lock:
            if client_id not in self.clients:
                return None
            
            key_data_bytes = self._secure_storage.retrieve(f'session_key_{client_id}')
            if key_data_bytes:
                # Deserialize the stored data
                key_data = json.loads(key_data_bytes.decode('utf-8'))
                # Convert hex string back to bytes
                session_key = bytes.fromhex(key_data['key'])
                
                # Update last used timestamp
                key_data['last_used'] = time.time()
                # Store updated data
                self._secure_storage.store(f'session_key_{client_id}', 
                                         json.dumps(key_data).encode('utf-8'))
                
                return session_key
            return None

    def _handle_client(self, client_socket: socket.socket, address: tuple):
        """Handle client connection and secure session establishment."""
        client_id = None
        try:
            log_event("Connection", f"[HANDLE_CLIENT] Starting client handler for address {address}")
            
            # Set socket timeout
            original_timeout = client_socket.gettimeout()
            client_socket.settimeout(self.connection_timeout)
            log_event("Connection", f"[HANDLE_CLIENT] Changed socket timeout from {original_timeout} to {self.connection_timeout}")
            
            # Generate client ID and store connection
            client_id = self._generate_client_id(address)
            log_event("Connection", f"[HANDLE_CLIENT] Generated client ID: {client_id}")
            log_event("Connection", f"[HANDLE_CLIENT] Socket timeout set to {self.connection_timeout} for {client_id}")

            # Store client information
            with self._clients_lock:
                log_event("Connection", f"[HANDLE_CLIENT] Acquired clients lock for {client_id}")
                try:
                    # Check if client already exists
                    if client_id in self.clients:
                        log_event("Connection", f"[HANDLE_CLIENT] Client {client_id} already exists, updating connection")
                        old_socket = self.clients[client_id].get('connection')
                        if old_socket:
                            try:
                                old_socket.close()
                                log_event("Connection", f"[HANDLE_CLIENT] Closed old socket for {client_id}")
                            except Exception as e:
                                log_error(ErrorCode.NETWORK_ERROR, 
                                        f"[HANDLE_CLIENT] Error closing old socket for {client_id}: {e}")

                    # Store new client data
                    self.clients[client_id] = {
                        'connection': client_socket,
                        'address': address,
                        'last_activity': time.time(),
                        'connection_time': time.time(),
                        'messages_received': 0,
                        'messages_sent': 0,
                        'state': 'connected'
                    }
                    log_event("Connection", f"[HANDLE_CLIENT] Client {client_id} information stored in clients dictionary")
                finally:
                    log_event("Connection", f"[HANDLE_CLIENT] Released clients lock for {client_id}")

            # TLS handling
            if self.tls_config and self.tls_config.enabled:
                log_event("Security", f"[HANDLE_CLIENT] TLS is enabled, starting handshake for {client_id}")
                try:
                    tls_wrapper = TLSWrapper(self.tls_config)
                    log_event("Security", f"[HANDLE_CLIENT] Created TLS wrapper for {client_id}")
                    
                    client_socket = tls_wrapper.wrap_socket(client_socket, server_side=True)
                    log_event("Security", f"[HANDLE_CLIENT] TLS handshake completed successfully for {client_id}")
                    
                    # Log TLS session info
                    cipher = client_socket.cipher()
                    log_event("Security", f"[HANDLE_CLIENT] TLS session info for {client_id}:")
                    log_event("Security", f"[HANDLE_CLIENT] - Cipher: {cipher[0]}")
                    log_event("Security", f"[HANDLE_CLIENT] - Protocol: {cipher[1]}")
                    log_event("Security", f"[HANDLE_CLIENT] - Bits: {cipher[2]}")
                    
                except Exception as e:
                    log_error(ErrorCode.SECURITY_ERROR, 
                             f"[HANDLE_CLIENT] TLS handshake failed for {client_id}: {str(e)}")
                    return

            # Session key generation and storage
            log_event("Security", f"[HANDLE_CLIENT] Generating session key for {client_id}")
            try:
                session_key = os.urandom(32)
                log_event("Security", f"[HANDLE_CLIENT] Generated {len(session_key)} byte session key")
                
                # Store session key in client data
                with self._clients_lock:
                    log_event("Security", f"[HANDLE_CLIENT] Acquiring lock to store session key for {client_id}")
                    self.clients[client_id]['session_key'] = session_key
                    self.clients[client_id]['connection'] = client_socket
                    self.clients[client_id]['state'] = 'key_generated'
                    log_event("Security", f"[HANDLE_CLIENT] Session key stored in client data for {client_id}")
                
                # Store in key manager and secure storage
                self.key_manager.set_session_key(client_id, session_key)
                self._store_client_session_key(client_id, session_key)
                log_event("Security", f"[HANDLE_CLIENT] Session key stored in key manager and secure storage for {client_id}")
                
            except Exception as e:
                log_error(ErrorCode.SECURITY_ERROR, 
                         f"[HANDLE_CLIENT] Failed to generate/store session key for {client_id}: {e}")
                raise

            # Message handling loop
            log_event("Communication", f"[HANDLE_CLIENT] Starting message handling loop for {client_id}")
            message_count = 0
            
            while self.running:
                try:
                    log_event("Communication", f"[HANDLE_CLIENT] Waiting for data from {client_id} (message {message_count + 1})")
                    data = receiveData(client_socket)
                    
                    if data:
                        message_count += 1
                        log_event("Communication", 
                                 f"[HANDLE_CLIENT] Received message {message_count} from {client_id}: {len(data)} bytes")
                        log_event("Communication", f"[HANDLE_CLIENT] First 100 bytes: {data[:100].hex()}")
                    else:
                        log_event("Connection", f"[HANDLE_CLIENT] Received empty data from {client_id}, closing connection")
                        break

                    # Update activity timestamp
                    with self._clients_lock:
                        if client_id in self.clients:
                            old_timestamp = self.clients[client_id]['last_activity']
                            self.clients[client_id]['last_activity'] = time.time()
                            self.clients[client_id]['messages_received'] += 1
                            log_event("Connection", 
                                     f"[HANDLE_CLIENT] Updated activity for {client_id}: "
                                     f"Delta = {time.time() - old_timestamp:.2f}s, "
                                     f"Total messages = {self.clients[client_id]['messages_received']}")
                        else:
                            log_error(ErrorCode.STATE_ERROR, 
                                    f"[HANDLE_CLIENT] Client {client_id} not found in clients dictionary")
                            break

                    try:
                        # Parse message
                        message_data = json.loads(data.decode('utf-8'))
                        message_type = message_data.get('type')
                        
                        log_event("Communication", 
                                 f"[HANDLE_CLIENT] Processing message {message_count} of type: {message_type}")
                        
                        # Process message based on type
                        if message_type == MessageType.KEY_EXCHANGE.value:
                            self.process_client_message(data, client_id)
                        elif message_type == MessageType.KEEPALIVE.value:
                            log_event("Connection", 
                                    f"[HANDLE_CLIENT] Received keepalive from {client_id}")
                            continue
                        else:
                            # Process other message types
                            self.process_client_message(data, client_id)
                            
                    except (json.JSONDecodeError, UnicodeDecodeError) as e:
                        log_event("Communication", 
                                 f"[HANDLE_CLIENT] Message {message_count} is not JSON, processing as binary: {str(e)}")
                        self.process_client_message(data, client_id)

                except socket.timeout:
                    log_event("Connection", f"[HANDLE_CLIENT] Socket timeout for {client_id}")
                    # Check for client timeout
                    with self._clients_lock:
                        if client_id in self.clients:
                            last_activity = self.clients[client_id]['last_activity']
                            inactive_time = time.time() - last_activity
                            log_event("Connection", 
                                     f"[HANDLE_CLIENT] Client {client_id} inactive for {inactive_time:.2f}s")
                            if inactive_time > self.connection_timeout:
                                log_event("Connection", 
                                         f"[HANDLE_CLIENT] Client {client_id} timed out after {inactive_time:.2f}s")
                                break
                    continue

                except Exception as e:
                    log_error(ErrorCode.GENERAL_ERROR, 
                             f"[HANDLE_CLIENT] Error handling message {message_count} from {client_id}: {str(e)}")
                    log_error(ErrorCode.GENERAL_ERROR, f"[HANDLE_CLIENT] Exception type: {type(e)}")
                    break

        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"[HANDLE_CLIENT] Fatal error in client handler for {client_id}: {str(e)}")
            log_error(ErrorCode.GENERAL_ERROR, f"[HANDLE_CLIENT] Exception type: {type(e)}")
            log_error(ErrorCode.GENERAL_ERROR, f"[HANDLE_CLIENT] Stack trace: ", exc_info=True)
        finally:
            log_event("Connection", f"[HANDLE_CLIENT] Cleaning up connection for {client_id}")
            log_event("Connection", f"[HANDLE_CLIENT] Final message count: {message_count}")
            if client_id:
                try:
                    with self._clients_lock:
                        if client_id in self.clients:
                            final_stats = self.clients[client_id]
                            log_event("Connection", f"[HANDLE_CLIENT] Final client stats for {client_id}:")
                            log_event("Connection", f"[HANDLE_CLIENT] - Messages received: {final_stats.get('messages_received', 0)}")
                            log_event("Connection", f"[HANDLE_CLIENT] - Messages sent: {final_stats.get('messages_sent', 0)}")
                            log_event("Connection", f"[HANDLE_CLIENT] - Connection duration: {time.time() - final_stats.get('connection_time', time.time()):.2f}s")
                            log_event("Connection", f"[HANDLE_CLIENT] - Final state: {final_stats.get('state', 'unknown')}")
                except Exception as e:
                    log_error(ErrorCode.GENERAL_ERROR, f"[HANDLE_CLIENT] Error logging final stats for {client_id}: {e}")
                
                self.close_client_connection(client_id)
                log_event("Connection", f"[HANDLE_CLIENT] Client handler completed for {client_id}")

    def process_encrypted_message(self, message_data: dict, client_id: str):
        """Process an encrypted message from a client."""
        try:
            # Get the session key for this client
            session_key = self.key_manager.get_session_key(client_id)
            if not session_key:
                log_error(ErrorCode.SECURITY_ERROR, f"No session key for client {client_id}")
                return

            # Decrypt the message
            encrypted_data = bytes.fromhex(message_data['data'])
            try:
                decrypted_message = Crypto.decrypt(
                    data=encrypted_data,
                    key=session_key,
                    associated_data=b'message'
                )
                log_event("Security", f"[SERVER] Message from {client_id} decrypted successfully")
            except Exception as e:
                log_error(ErrorCode.CRYPTO_ERROR, f"Failed to decrypt message from {client_id}: {str(e)}")
                return

            # Process the decrypted message
            message_text = decrypted_message.decode('utf-8')
            log_event("Communication", f"Received message from {client_id}: {message_text}")

            # Send acknowledgment
            response = {
                'type': MessageType.MESSAGE_ACK.value,
                'nonce': self.nonce_manager.generate_nonce(),
                'timestamp': int(time.time())
            }
            response_bytes = json.dumps(response).encode('utf-8')
            sendData(self.clients[client_id]['connection'], response_bytes)

        except Exception as e:
            log_error(ErrorCode.COMMUNICATION_ERROR, f"Error processing message from {client_id}: {str(e)}")
