import threading
import socket
import json
import time
import os
from typing import Dict, Optional, Tuple
from datetime import datetime
import traceback
import ssl
import errno

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
        self._client_threads = []
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
        """Start the server."""
        try:
            if not self._initialized:
                raise StateError("Server not properly initialized")
            
            self.running = True
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            
            log_event("Server", f"Server started on {self.host}:{self.port}")
            
            # Start accept thread
            self._accept_thread = threading.Thread(target=self._accept_connections)
            self._accept_thread.daemon = True  # Make thread daemon so it exits when main thread exits
            self._accept_thread.start()
            
        except Exception as e:
            self.running = False
            log_error(ErrorCode.STARTUP_ERROR, f"Failed to start server: {e}")
            raise

    def _accept_connections(self):
        """Accept incoming connections."""
        try:
            # Don't set a timeout - let accept() block
            self.server_socket.settimeout(None)
            
            while self.running:
                try:
                    client_socket, client_address = self.server_socket.accept()
                    if not self.running:
                        client_socket.close()
                        return
                    
                    log_event("Server", f"Accepted connection from {client_address[0]}:{client_address[1]}")
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_address)
                    )
                    client_thread.start()
                    self._client_threads.append(client_thread)
                    
                except socket.error:
                    if not self.running:
                        return
                    # Only raise if we're still supposed to be running
                    if self.running:
                        raise
                
        except Exception as e:
            if self.running:
                log_error(ErrorCode.GENERAL_ERROR, f"Error in accept loop: {e}")


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
                conn = client_data['socket']
                
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
        try:
            log_event("Server", "Starting server shutdown...")
            self.running = False  # Signal threads to stop
            
            # Force accept loop to exit
            self._force_accept_exit()
            
            # Close all client connections first
            with self.clients_lock:
                client_ids = list(self.clients.keys())
                for client_id in client_ids:
                    self._cleanup_client(client_id)
                self.clients.clear()
            
            # Close server socket
            if self.server_socket:
                try:
                    self.server_socket.close()
                    self.server_socket = None
                except socket.error:
                    pass
            
            # Wait for accept thread to finish (reduced timeout)
            if hasattr(self, '_accept_thread') and self._accept_thread and self._accept_thread.is_alive():
                self._accept_thread.join(timeout=0.5)  # Reduced timeout from 2 to 0.5 seconds
            
            # Stop cleanup thread if exists
            if hasattr(self, 'key_manager'):
                self.key_manager.stop_cleanup_thread()
            
            # Join all client handler threads (reduced timeout)
            for thread in self._client_threads:
                if thread.is_alive():
                    thread.join(timeout=0.5)  # Reduced timeout from 2 to 0.5 seconds
            
            log_event("Server", "Server shutdown completed")
            
        except Exception as e:
            log_error(ErrorCode.SHUTDOWN_ERROR, f"Error during server shutdown: {e}")

    def process_client_message(self, data: bytes, client_id: str):
        """Process a message received from a client."""
        try:
            # Add validation
            if not data or not client_id:
                raise ValueError("Invalid message data or client ID")
            
            if client_id not in self.clients:
                raise ValueError("Unknown client ID")
            
            message = json.loads(data.decode('utf-8'))
            
            # Handle session termination
            if message.get('type') == MessageType.SESSION_TERMINATION.value:
                log_event("Connection", f"Received termination request from {client_id}")
                self.close_client_connection(client_id)
                return
            
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
            log_error(ErrorCode.GENERAL_ERROR, f"Error processing message: {e}")
            # Consider closing connection on critical errors
            if isinstance(e, (SecurityError, StateError)):
                self.close_client_connection(client_id)

    def _handle_key_exchange(self, message: dict, client_id: str):
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
            self.send_message(client_id, "Key exchange failed", MessageType.ERROR)
            raise

    def send_message(self, client_id: str, message: str, message_type: MessageType = MessageType.DATA) -> bool:
        """
        Send a message to a client with specified message type.
        
        Args:
            client_id (str): ID of the client to send message to
            message (str): Message content to send
            message_type (MessageType): Type of message (DATA or ERROR), defaults to DATA
            
        Returns:
            bool: True if message sent successfully, False otherwise
        """
        try:
            # For DATA messages, verify first message received
            if message_type == MessageType.DATA and not self.received_first_message.get(client_id, False):
                log_error(ErrorCode.STATE_ERROR, 
                         f"Cannot send DATA message to {client_id} before receiving first message")
                return False

            # Get client socket and session info
            with self.clients_lock:
                if client_id not in self.clients:
                    log_error(ErrorCode.VALIDATION_ERROR, f"Unknown client ID: {client_id}")
                    return False
                client_socket = self.clients[client_id]['socket']

            # For DATA messages, encrypt with session key
            if message_type == MessageType.DATA:
                session_key = self.key_manager.get_session_key(client_id)
                if not session_key:
                    log_error(ErrorCode.SECURITY_ERROR, "No session key available")
                    return False
                    
                # Encrypt message
                ciphertext, nonce, tag = Crypto.encrypt(
                    data=message.encode('utf-8'),
                    key=session_key
                )
                
                message_data = {
                    'encryptedMessage': ciphertext.hex(),
                    'nonce': nonce.hex(),
                    'tag': tag.hex(),
                }
            else:
                # For ERROR messages, send unencrypted
                message_data = {
                    'encryptedMessage': message,
                    'nonce': self.nonce_manager.generate_nonce(),
                    'tag': '',
                }

            # Common message fields
            message_data.update({
                'signature': '',
                'timestamp': int(time.time()),
                'type': message_type.value,
                'sender_id': 'server'
            })

            # Package and send the message
            response = packageMessage(**message_data)
            sendData(client_socket, response)
            log_event("Communication", f"Sent {message_type.name} message to client {client_id}")

            # Handle acknowledgment for DATA messages
            if message_type == MessageType.DATA:
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
                            log_event("Communication", 
                                     f"SERVER RECEIVED ACK from {client_id}: {decrypted_ack.decode('utf-8')}")
                except socket.timeout:
                    log_event("Communication", f"No acknowledgment received from {client_id} within timeout")
                finally:
                    client_socket.settimeout(self.socket_timeout)  # Restore original timeout

            return True

        except Exception as e:
            log_error(ErrorCode.COMMUNICATION_ERROR, f"Failed to send message: {e}")
            return False

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
                    # Use our TLSWrapper so that the TLS configuration and handshake
                    # are applied symmetrically on both client and server.
                    from security.TLSWrapper import TLSWrapper
                    tls_wrapper = TLSWrapper(self.tls_config, client_mode=False)
                    client_socket = tls_wrapper.wrap_socket(
                        client_socket,
                        server_side=True,
                        do_handshake_on_connect=True
                    )
                    
                    # If client certificates must be verified, check that the peer certificate is supplied.
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
            
            # Add connection state tracking
            with self.clients_lock:
                self.clients[client_id]['connection_state'] = 'connected'
            
            # Handle cleanup on exit    
            try:
                self._handle_messages(client_id)
            finally:
                with self.clients_lock:
                    if client_id in self.clients:
                        self.clients[client_id]['connection_state'] = 'disconnected'
                self._cleanup_client(client_id)
                
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
                    # Check if socket is still valid before receiving
                    if client_socket.fileno() == -1:
                        log_event("Connection", f"[HANDLE_MESSAGES] Socket invalid for client {client_id}")
                        break

                    data = receiveData(client_socket)
                    if data is None:  # Connection closed or error
                        log_event("Connection", f"[HANDLE_MESSAGES] Client {client_id} disconnected")
                        break
                    
                    # Process the received data
                    self._update_client_activity(client_id)
                    self.process_client_message(data, client_id)
                    
                except socket.timeout:
                    # Don't break on timeout, just continue listening
                    continue
                except socket.error as e:
                    if e.errno in (errno.ECONNRESET, errno.EPIPE, errno.EBADF):
                        log_error(ErrorCode.NETWORK_ERROR, f"Connection error for client {client_id}: {e}")
                        break
                    raise  # Re-raise unexpected socket errors
                except Exception as e:
                    log_error(ErrorCode.GENERAL_ERROR, f"Error handling message from {client_id}: {e}")
                    break
                
        finally:
            # Ensure proper cleanup
            self._cleanup_client(client_id)

    def _update_client_activity(self, client_id: str):
        """Update the last activity timestamp for a client."""
        try:
            with self.clients_lock:
                if client_id in self.clients:
                    prev_time = self.clients[client_id]['last_activity']
                    current_time = time.time()
                    self.clients[client_id]['last_activity'] = current_time
                    self.clients[client_id]['messages_received'] += 1
                    delta = current_time - prev_time
                    log_event("Connection", 
                            f"[HANDLE_CLIENT] Updated activity for {client_id}: "
                            f"Delta = {delta:.2f}s, "
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

    def _force_accept_exit(self):
        """Force the accept loop to exit by connecting to self."""
        try:
            if self.server_socket:
                # Create a temporary socket and connect to self to break accept()
                tmp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    tmp_socket.connect((self.host, self.port))
                except:
                    pass
                finally:
                    tmp_socket.close()
        except:
            pass

