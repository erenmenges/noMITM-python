import threading
import socket
import json
import time
import os
from typing import Dict, Optional, Tuple
from datetime import datetime
import traceback
import ssl

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
    def __init__(self, host: str, port: int, tls_config: Optional[TLSConfig] = None):
        """Initialize server with optional TLS configuration.
        
        Args:
            host (str): Host address to bind to
            port (int): Port to listen on
            tls_config (Optional[TLSConfig]): TLS configuration, defaults to disabled
        """
        self.host = host
        self.port = port
        self.socket_timeout = 30
        # Initialize with default values
        self.tls_config = tls_config or TLSConfig(enabled=False)
        self._lock = threading.Lock()
        self.clients_lock = threading.Lock()
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
        self.received_first_message = {}  # Track first message status per client
        
    def _initialize_certificates(self):
        """Initialize server certificates and validation chain."""
        try:
            # First generate a key pair if one doesn't exist
            if not self.key_manager.has_key_pair():
                self.key_manager.generate_key_pair()
            
            # Load server certificate and private key
            self.certificate = self.key_manager.load_certificate(
                str(self.tls_config.cert_path)
            )
            self.private_key = self.key_manager.get_private_key()
            
            # Load CA certificate for client validation
            self.ca_certificate = self.key_manager.load_certificate(
                str(self.tls_config.ca_path)
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

    def cleanup_inactive_clients(self):
        """Remove inactive client connections."""
        current_time = time.time()
        inactive_clients = []
        
        with self.clients_lock:  # Add thread safety
            for client_id, client_data in self.clients.items():
                if current_time - client_data['last_activity'] > self.connection_timeout:
                    inactive_clients.append(client_id)
                    
            for client_id in inactive_clients:
                self.close_client_connection(client_id)

    def close_client_connection(self, client_id: str):
        """Safely close client connection with proper key cleanup."""
        with self.clients_lock:
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
                
                # If it's a DATA message, decrypt and print it
                if message['type'] == MessageType.DATA.value:
                    decrypted_message = self._process_secure_message(message, client_id)
                    if decrypted_message:
                        print(f"\nReceived message from {client_id}: {decrypted_message}\n")
                        
                        # Mark that we've received first message from this client
                        self.received_first_message[client_id] = True
                        
                        # Get session key for encryption
                        session_key = self.key_manager.get_session_key(client_id)
                        if not session_key:
                            raise SecurityError("No session key available")
                        
                        # Create acknowledgment message
                        ack_content = f"Message received: {decrypted_message[:20]}..."
                        
                        # Encrypt acknowledgment with nonce and tag
                        ciphertext, nonce, tag = Crypto.encrypt(
                            ack_content.encode('utf-8'),
                            session_key
                        )
                        
                        # Package encrypted acknowledgment
                        response = packageMessage(
                            encryptedMessage=ciphertext.hex(),
                            signature='',
                            nonce=nonce.hex(),
                            tag=tag.hex(),
                            timestamp=int(time.time()),
                            type=MessageType.ACKNOWLEDGE.value,
                            sender_id='server'
                        )
                        
                        # Send acknowledgment
                        sendData(self.clients[client_id]['socket'], response)
                        log_event("Communication", f"Sent acknowledgment to client {client_id}")
                
            except json.JSONDecodeError as e:
                log_error(ErrorCode.VALIDATION_ERROR, f"[PROCESS_MESSAGE] JSON decode error: {str(e)}")
                message = parseMessage(data)

        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"[PROCESS_MESSAGE] Error processing message: {str(e)}")
            log_error(ErrorCode.GENERAL_ERROR, f"[PROCESS_MESSAGE] Exception type: {type(e)}")

    def _handle_key_exchange(self, message: dict, client_id: str) -> None:
        """Handle key exchange request from client."""
        try:
                # Load client's public key
            client_public_key = serialization.load_pem_public_key(
                message['public_key'].encode('utf-8'),
                backend=default_backend()
            )
            
            # Generate server's key pair if needed
            if not self.key_manager.has_key_pair():
                self.key_manager.generate_key_pair()
            
            # Get server's private key
            server_private_key = self.key_manager.get_private_key()
            
            # Derive shared key using Crypto class
            shared_key = Crypto.derive_session_key(
                peer_public_key=client_public_key,
                private_key=server_private_key,
                context=b'session key'
            )
            
            # Store the session key for this client
            self.key_manager.store_session_key(client_id, shared_key)
            # Add debug log for session key
            log_event("Security", f"[DEBUG] Server session key for {client_id} (hex): {shared_key.hex()}")
            
            # Create response with server's public key and assigned client_id
            response = {
                'type': MessageType.KEY_EXCHANGE_RESPONSE.value,
            'public_key': self.key_manager.get_public_key_pem().decode('utf-8'),
                'nonce': self.nonce_manager.generate_nonce(),
                'timestamp': int(time.time()),
            'client_id': client_id
            }

            # Send response - use 'socket' instead of 'connection'
            response_bytes = json.dumps(response).encode('utf-8')
            sendData(self.clients[client_id]['socket'], response_bytes)  # Changed from 'connection' to 'socket'
                
        except Exception as e:
            log_error(ErrorCode.KEY_EXCHANGE_ERROR, f"Key exchange failed: {e}")
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

    def send_response_message(self, client_id: str, message: str) -> bool:
        """Send an encrypted response message to a client."""
        try:
            # Check if we've received first message from this client
            if not self.received_first_message.get(client_id, False):
                log_error(ErrorCode.STATE_ERROR, 
                         f"Cannot send message to {client_id} before receiving first message")
                return False

            # Get client session key
            session_key = self.key_manager.get_session_key(client_id)
            if not session_key:
                log_error(ErrorCode.SECURITY_ERROR, "No session key available")
                return False

            # Get client socket
            with self.clients_lock:
                if client_id not in self.clients:
                    log_error(ErrorCode.VALIDATION_ERROR, f"Unknown client ID: {client_id}")
                    return False
                client_socket = self.clients[client_id]['socket']

            # Encrypt message
            ciphertext, nonce, tag = Crypto.encrypt(
                data=message.encode('utf-8'),
                key=session_key
            )

            # Create message data with type
            message_type = MessageType.DATA.value
            message_data = {
                'encryptedMessage': ciphertext.hex(),
                'signature': '',
                'nonce': nonce.hex(),
                'tag': tag.hex(),
                'timestamp': int(time.time()),
                'type': message_type,
                'sender_id': 'server'
            }

            # Package and send the message
            response = packageMessage(**message_data)
            sendData(client_socket, response)
            log_event("Communication", f"Sent message to client {client_id}")

            # Only wait for acknowledgment if we're sending a DATA message
            if message_type == MessageType.DATA.value:
                try:
                    client_socket.settimeout(5)
                    ack_data = receiveData(client_socket)
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
                            log_event("Communication", f"SERVER RECEIVED ACK from {client_id}: {decrypted_ack.decode('utf-8')}")
                except socket.timeout:
                    log_event("Communication", f"No acknowledgment received from {client_id} within timeout")
                finally:
                    client_socket.settimeout(self.socket_timeout)  # Restore original timeout

            return True

        except Exception as e:
            log_error(ErrorCode.COMMUNICATION_ERROR, f"Failed to send response message: {e}")
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
            
            with self.clients_lock:
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
            with self.clients_lock:
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
            with self.clients_lock:
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
        with self.clients_lock:
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
            with self.clients_lock:
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
            with self.clients_lock:
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

    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle new client connection with certificate validation and message handling."""
        try:
            log_event("Connection", f"[HANDLE_CLIENT] Starting client handler for {address}")
            log_event("Connection", f"[HANDLE_CLIENT] Socket state - Connected: {client_socket.fileno() != -1}")
            
            # TLS handling
            client_cert = None
            if self.tls_config and self.tls_config.enabled:
                log_event("Security", f"[HANDLE_CLIENT] TLS enabled, wrapping socket for {address}")
                try:
                    # Create TLS context
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    
                    # Configure TLS settings
                    context.load_cert_chain(
                        certfile=str(self.tls_config.cert_path),
                        keyfile=str(self.tls_config.key_path)
                    )
                    context.load_verify_locations(cafile=str(self.tls_config.ca_path))
                    
                    if self.tls_config.verify_mode == "CERT_REQUIRED":
                        context.verify_mode = ssl.CERT_REQUIRED
                    
                    # Wrap socket
                    client_socket = context.wrap_socket(
                        client_socket,
                        server_side=True,
                        do_handshake_on_connect=True
                    )
                    
                    # Now we can validate the certificate
                    if self.tls_config.verify_mode == "CERT_REQUIRED":
                        client_cert = client_socket.getpeercert()
                        if not client_cert:
                            raise ValueError("No client certificate provided")
                        log_event("Security", f"[HANDLE_CLIENT] Certificate validated for {address}")
                        
                except Exception as e:
                    log_error(ErrorCode.AUTHENTICATION_ERROR, f"TLS setup failed: {e}")
                    client_socket.close()
                    return
            
            # Set socket timeout
            log_event("Connection", f"[HANDLE_CLIENT] Attempting to set socket timeout to {self.socket_timeout}")
            client_socket.settimeout(self.socket_timeout)
            log_event("Connection", f"[HANDLE_CLIENT] Socket timeout set successfully to {client_socket.gettimeout()}")
            
            # Generate unique client ID
            client_id = f"{address[0]}:{address[1]}_{time.time()}"
            log_event("Connection", f"[HANDLE_CLIENT] Generated client ID: {client_id}")

            # Store client information
            log_event("Connection", f"[HANDLE_CLIENT] Storing client information for {client_id}")
            with self.clients_lock:
                self.clients[client_id] = {
                    'address': address,
                    'last_activity': time.time(),
                    'messages_received': 0,
                    'socket': client_socket,
                    'certificate': client_cert
                }
                log_event("Connection", f"[HANDLE_CLIENT] Client information stored successfully")
            
            # Start message handling loop
            log_event("Communication", f"[HANDLE_CLIENT] Starting message handling loop for {client_id}")
            self._handle_messages(client_id)
                
        except Exception as e:
            log_error(ErrorCode.CONNECTION_ERROR, f"Error handling client {address}: {e}")
            log_error(ErrorCode.CONNECTION_ERROR, f"Exception type: {type(e)}")
            log_error(ErrorCode.CONNECTION_ERROR, f"Stack trace: {traceback.format_exc()}")
            try:
                if client_socket.fileno() != -1:  # Check if socket is still valid
                    client_socket.close()
                    log_event("Connection", f"[HANDLE_CLIENT] Closed socket for {address} after error")
            except:
                pass

    def _handle_messages(self, client_id: str):
        """Handle incoming messages from a client."""
        try:
            client_info = self.clients[client_id]
            client_socket = client_info['socket']
            
            while True:
                try:
                    data = receiveData(client_socket)
                    if data is None:  # Connection closed or error
                        log_event("Connection", f"[HANDLE_MESSAGES] Client {client_id} disconnected")
                        break  # Exit the loop when connection is closed
                    
                    # Process the received data
                    self._update_client_activity(client_id)
                    self.process_client_message(data, client_id)
                    
                except socket.timeout:
                    continue  # Just continue on timeout
                except socket.error as e:
                    log_error(ErrorCode.NETWORK_ERROR, f"Socket error for client {client_id}: {e}")
                    break
                except CommunicationError as e:
                    log_error(ErrorCode.COMMUNICATION_ERROR, f"Communication error for client {client_id}: {e}")
                    break
                except Exception as e:
                    log_error(ErrorCode.GENERAL_ERROR, f"Error handling message from {client_id}: {e}")
                    break
                
        finally:
            # Clean up client connection
            self._cleanup_client(client_id)  # Use the dedicated cleanup method

    def _update_client_activity(self, client_id: str):
        """Update the last activity timestamp for a client."""
        try:
            with self.clients_lock:
                        if client_id in self.clients:
                            self.clients[client_id]['last_activity'] = time.time()
                            self.clients[client_id]['messages_received'] += 1
                            log_event("Connection", 
                                     f"[HANDLE_CLIENT] Updated activity for {client_id}: "
                        f"Delta = {time.time() - self.clients[client_id]['last_activity']:.2f}s, "
                                     f"Total messages = {self.clients[client_id]['messages_received']}")
        except Exception as e:
            log_error(ErrorCode.STATE_ERROR, f"Failed to update client activity: {e}")

    def _cleanup_client(self, client_id: str):
        """Clean up resources for a disconnected client."""
        try:
            with self.clients_lock:
                if client_id in self.clients:
                    client_info = self.clients[client_id]
                    
                    # Close socket
                    try:
                        if client_info['socket'].fileno() != -1:
                            try:
                                client_info['socket'].shutdown(socket.SHUT_RDWR)
                            except:
                                pass
                            client_info['socket'].close()
                    except:
                        pass
                    
                    # Remove from clients dict
                    del self.clients[client_id]
                    
                    # Clean up session keys
                    try:
                        self._secure_storage.remove(f'session_key_{client_id}')
                    except:
                        pass
                    
                    log_event("Connection", f"[CLEANUP] Cleaned up resources for client {client_id}")
                
        except Exception as e:
            log_error(ErrorCode.CLEANUP_ERROR, f"Error cleaning up client {client_id}: {e}")

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

    def _process_secure_message(self, message_data: dict, client_id: str) -> Optional[str]:
        """Process an encrypted message."""
        try:
            # Extract message components
            ciphertext = bytes.fromhex(message_data['encryptedMessage'])
            nonce = bytes.fromhex(message_data['nonce'])
            tag = bytes.fromhex(message_data['tag'])
            
            # Create associated data matching the sender's - only stable fields
            aad_dict = {
                'sender_id': message_data['sender_id'],
                'sequence': message_data['sequence']
                # Exclude timestamp from AAD
            }
            associated_data = json.dumps(aad_dict, sort_keys=True).encode('utf-8')
            
            # Get session key and decrypt
            session_key = self.key_manager.get_session_key(client_id)
            if not session_key:
                raise SecurityError("No session key available")
            
            plaintext = Crypto.decrypt(
                ciphertext=ciphertext,
                    key=session_key,
                nonce=nonce,
                tag=tag,
                associated_data=associated_data
            )
            
            return plaintext.decode('utf-8')

        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"Failed to process secure message: {e}")
            raise

    def get_client_ids(self) -> list:
        """
        Get a list of all connected client IDs.
        
        Returns:
            list: List of client IDs currently connected to the server
        """
        with self.clients_lock:
            return list(self.clients.keys())

