from Communications import packageMessage, parseMessage, sendData, receiveData, MessageType
from Crypto import Crypto, SecureMessage
from KeyManagement import KeyManagement
from Utils import NonceManager, log_event, log_error, ErrorCode
import threading
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import time
from security.TLSWrapper import TLSWrapper
from typing import Dict, Optional
from cryptography import x509
from cryptography.x509.oid import ExtensionOID

class Server:
    def __init__(self, host: str, port: int, tls_config=None):
        self.host = host
        self.port = port
        self.tls_config = tls_config
        self._lock = threading.Lock()
        self._clients_lock = threading.Lock()
        self.clients: Dict[str, dict] = {}
        self.running = False
        self.server_socket = None
        self.key_manager = KeyManagement()
        self.certificate = None
        self.private_key = None
        self.ca_certificate = None
        self.connection_timeout = 30
        
        # Initialize certificates if TLS is enabled
        if tls_config and tls_config.enabled:
            self._initialize_certificates()

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

    def close_client_connection(self, client_id):
        """Safely close a client connection with proper cleanup."""
        with self._clients_lock:
            if client_id in self.clients:
                try:
                    client_data = self.clients[client_id]
                    conn = client_data['connection']
                    
                    # Send termination message if possible
                    try:
                        termination_message = packageMessage(
                            encryptedMessage='',
                            signature='',
                            nonce=self.nonce_manager.generate_nonce(),
                            timestamp=int(time.time()),
                            type=MessageType.SESSION_TERMINATION
                        )
                        sendData(conn, termination_message)
                    except Exception as e:
                        log_error(ErrorCode.NETWORK_ERROR, f"Failed to send termination message: {e}")
                    
                    # Proper socket shutdown sequence
                    try:
                        conn.shutdown(socket.SHUT_RDWR)
                    except socket.error:
                        pass  # Socket might already be closed
                    finally:
                        try:
                            conn.close()
                        except socket.error:
                            pass

                    # Clean up cryptographic material
                    if 'session_key' in client_data:
                        key_data = client_data['session_key']
                        if isinstance(key_data, bytes):
                            client_data['session_key'] = b'\x00' * len(key_data)
                        self.key_manager.remove_session_key(client_id)
                    
                    del self.clients[client_id]
                    log_event("Connection", f"Client {client_id} disconnected and cleaned up")
                    
                except Exception as e:
                    log_error(ErrorCode.NETWORK_ERROR, f"Error during client cleanup: {e}")
                finally:
                    # Ensure client is removed even if cleanup fails
                    if client_id in self.clients:
                        del self.clients[client_id]

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
            message = parseMessage(data)
            timestamp = message.get('timestamp', 0)
            current_time = int(time.time())
            
            # Reject messages older than 5 minutes or future messages
            if abs(current_time - timestamp) > 300:
                log_error(ErrorCode.VALIDATION_ERROR, "Message timestamp outside acceptable range")
                return
            
            # Parse and validate the message
            message = parseMessage(data)
            message_type = message.get('type')
            
            # Get client connection
            with self._clients_lock:
                if client_id not in self.clients:
                    log_error(ErrorCode.VALIDATION_ERROR, f"Unknown client ID: {client_id}")
                    return
                client_data = self.clients[client_id]
                conn = client_data['connection']

            # Handle different message types
            if message_type == MessageType.DATA.value:
                try:
                    # Decrypt message using session key
                    secure_msg = SecureMessage.from_dict(message)
                    decrypted_message = Crypto.decrypt(secure_msg, client_data.get('session_key'))
                    
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
                    
                    # After acknowledgment, send a response message
                    self.send_response_message(client_id, f"Server received: {decrypted_message}")
                    
                except Exception as e:
                    log_error(ErrorCode.ENCRYPTION_ERROR, f"Failed to process encrypted message: {e}")
                    self._send_error_response(conn, "Failed to process message")
            elif message_type == MessageType.KEY_RENEWAL_REQUEST.value:
                try:
                    # Handle key renewal request
                    new_public_key = message.get('newPublicKey')
                    if not new_public_key:
                        raise ValueError("Missing new public key in renewal request")
                    
                    # Generate new server key pair
                    server_public_pem, server_private_pem = Crypto.generate_key_pair()
                    
                    # Update client's session data
                    with self._clients_lock:
                        if client_id in self.clients:
                            client_data['public_key'] = serialization.load_pem_public_key(
                                new_public_key.encode(),
                                backend=default_backend()
                            )
                            
                    # Send response with server's new public key
                    response = packageMessage(
                        encryptedMessage=server_public_pem.decode(),
                        signature='',
                        nonce=self.nonce_manager.generate_nonce(),
                        timestamp=int(time.time()),
                        type=MessageType.KEY_RENEWAL_RESPONSE.value
                    )
                    sendData(conn, response)
                    
                    # Update server's private key for this client
                    self.key_manager.update_client_key(client_id, server_private_pem)
                    
                except Exception as e:
                    log_error(ErrorCode.KEY_MANAGEMENT_ERROR, f"Key renewal failed: {e}")
                    self._send_error_response(conn, "Key renewal failed")
                    
            elif message_type == MessageType.SESSION_TERMINATION.value:
                log_event("Connection", f"Received termination request from client {client_id}")
                self.close_client_connection(client_id)
                
            else:
                log_error(ErrorCode.VALIDATION_ERROR, f"Unknown message type: {message_type}")
                self._send_error_response(conn, "Unknown message type")
                
        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Error processing client message: {e}")
            try:
                with self._clients_lock:
                    if client_id in self.clients:
                        self._send_error_response(self.clients[client_id]['connection'], str(e))
            except Exception:
                pass

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
        """Send an encrypted response message to a client."""
        try:
            with self._clients_lock:
                if client_id not in self.clients:
                    log_error(ErrorCode.VALIDATION_ERROR, f"Unknown client ID: {client_id}")
                    return
                client_data = self.clients[client_id]
                conn = client_data['connection']
                session_key = client_data.get('session_key')

            if not session_key or len(session_key) != CryptoConstants.AES_KEY_SIZE:
                log_error(ErrorCode.ENCRYPTION_ERROR, "Invalid or missing session key")
                return

            # Encrypt the response message
            iv, ciphertext, tag = Crypto.aes_encrypt(message.encode('utf-8'), session_key)
            
            # Package and send the response
            response = packageMessage(
                encryptedMessage=ciphertext.hex(),
                signature='',  # Add signature if needed
                nonce=self.nonce_manager.generate_nonce(),
                timestamp=int(time.time()),
                type=MessageType.SERVER_RESPONSE.value,
                iv=iv.hex(),
                tag=tag.hex()
            )
            
            sendData(conn, response)
            log_event("Message", f"Sent response to client {client_id}")
            
        except ConnectionError as e:
            log_error(ErrorCode.NETWORK_ERROR, f"Connection lost while sending response: {e}")
            self.close_client_connection(client_id)
        except Exception as e:
            log_error(ErrorCode.NETWORK_ERROR, f"Failed to send response message: {e}")
            self._send_error_response(conn, "Internal server error")
