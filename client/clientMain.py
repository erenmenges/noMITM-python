import threading
import socket
from Communications import packageMessage, parseMessage, sendData, receiveData, MessageType
from Crypto import Crypto, SecureMessage
from KeyManagement import KeyManagement
from Utils import NonceManager, log_event, log_error, ErrorCode, ErrorMessage, throw_error
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from security.TLSWrapper import TLSWrapper
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID

class Client:
    def __init__(self):
        self._lock = threading.Lock()
        # Initialize key management and nonce manager
        self.key_manager = KeyManagement()
        self.nonce_manager = NonceManager()
        self.session_key = None
        self.listening = False
        self.listen_thread = None
        self.destination = None
        self.private_key = None  # Add attribute to store client's private key
        self.public_key = None   # Add attribute to store client's public key
        self.socket = None  # Add attribute to store the active socket
        self.certificate = None  # Add certificate attribute
        self.server_certificate = None  # Add server certificate attribute

        # Schedule automated key renewal every 3600 seconds (1 hour)
        renewal_interval = 3600
        self.key_manager.schedule_key_renewal(renewal_interval)

    def set_session_key(self, key):
        with self._lock:
            self.session_key = key
            log_event("Session", "Session key updated")

    def establish_session(self, destination):
        """
        Establishes a secure session with the server.
        
        Args:
            destination (tuple): A tuple containing the server's IP and port.
        """
        with self._lock:
            if self.socket:
                self.terminate_session()
            
            try:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(30)
                
                # Connect first, then wrap with TLS
                self.socket.connect(destination)
                log_event("Network", f"Connected to server at {destination}.")

                # If TLS is enabled, wrap the socket and perform certificate exchange
                if hasattr(self, 'tls_config') and self.tls_config.enabled:
                    # Load client certificate if configured
                    if self.tls_config.cert_path:
                        self.certificate = self.key_manager.load_certificate(self.tls_config.cert_path)
                        log_event("Security", "Client certificate loaded.")

                    tls_wrapper = TLSWrapper(self.tls_config)
                    self.socket = tls_wrapper.wrap_socket(
                        self.socket,
                        server_side=False,
                        server_hostname=destination[0]
                    )
                    log_event("Security", "TLS connection established.")

                    # Get and validate server certificate
                    self.server_certificate = self.socket.getpeercert(binary_form=True)
                    if self.server_certificate:
                        self.server_certificate = load_pem_x509_certificate(
                            self.server_certificate,
                            default_backend()
                        )
                        self._validate_server_certificate()
                        log_event("Security", "Server certificate validated.")

                # Continue with existing key exchange logic
                # Generate the client's key pair for secure communication
                public_pem, private_pem = Crypto.generate_key_pair()
                log_event("Key Generation", "Client key pair generated.")

                # Send the client's public key to the server
                self.socket.sendall(public_pem)
                log_event("Key Exchange", "Sent public key to server.")

                # Receive the server's public key
                server_public_pem = self.socket.recv(2048)
                log_event("Key Exchange", "Received public key from server.")

            except Exception as e:
                if self.socket:
                    self.socket.close()
                    self.socket = None
                log_error(ErrorCode.NETWORK_ERROR, f"Failed to establish session: {e}")
                raise

        # Load the server's public key
        try:
            server_public_key = serialization.load_pem_public_key(
                server_public_pem,
                backend=default_backend()
            )
            log_event("Key Exchange", "Server public key loaded successfully.")
            self.server_public_key = server_public_key
        except Exception as e:
            log_event("Error", f"Failed to load server public key: {e}")
            self.terminate_session()
            return False

        # Load the client's private key
        try:
            self.private_key = serialization.load_pem_private_key(
                private_pem,
                password=None,
                backend=default_backend()
            )
            log_event("Key Management", "Client private key loaded successfully.")
        except Exception as e:
            log_event("Error", f"Failed to load client private key: {e}")
            return

        # Derive the shared session key using ECDH
        try:
            context = b"session key derivation"
            self.session_key = Crypto.derive_session_key(server_public_key, self.private_key, context)
            log_event("Session", "Session key derived successfully.")
        except Exception as e:
            log_event("Error", f"Failed to derive session key: {e}")
            return

        return True

    def send_message(self, message):
        """
        Sends a signed message to the server.
        
        Args:
            message (str): The message to send.
        """
        if not self.socket or not self.session_key or not self.private_key:
            log_event("Error", "Invalid client state for sending messages")
            raise RuntimeError("Client not properly initialized")

        # Encrypt the message using the session key
        iv, ciphertext, tag = Crypto.aes_encrypt(message.encode('utf-8'), self.session_key)
        log_event("Encryption", "Message encrypted successfully.")

        # Package the message without signature first
        nonce = self.nonce_manager.generate_nonce()
        message_package = packageMessage(
            encryptedMessage=ciphertext.hex(),
            signature='',  # Placeholder
            nonce=nonce,
            timestamp=self.nonce_manager.get_current_timestamp(),
            type="data",
            iv=iv.hex()
        )

        # Sign the entire message package
        signature = self.key_manager.sign_message(self.private_key, message_package.encode('utf-8'))
        log_event("Message Signing", "Message signed successfully.")

        # Update the message package with the signature
        message_package_dict = {
            "encryptedMessage": ciphertext.hex(),
            "nonce": nonce,
            "timestamp": self.nonce_manager.get_current_timestamp(),
            "type": "data",
            "iv": iv.hex(),
            "signature": signature.hex(),
            "tag": tag.hex()
        }
        message_package_signed = packageMessage(**message_package_dict)

        try:
            # Send the signed message using the active socket
            sendData(self.socket, message_package_signed)  # Fixed parameter to use self.socket
            log_event("Network", "Message sent to the server.")
        except Exception as e:
            log_event("Error", f"Failed to send message: {e}")  # Fixed incomplete logging

    def receive_messages(self):
        """
        Listens for incoming messages from the server.
        """
        if not self.session_key:
            log_event("Error", "Session not established. Cannot receive messages.")
            return

        while self.listening:
            try:
                received_package = receiveData(self.socket)
                if not received_package:
                    continue

                # Parse the received message
                parsed_message = parseMessage(received_package)
                log_event("Network", "Message received from server.")

                # Process the message
                self.process_server_message(parsed_message)

            except socket.timeout:
                continue
            except Exception as e:
                log_event("Error", f"Failed to receive or process message: {e}")
                if isinstance(e, ConnectionError):
                    break

    def handle_key_renewal_request(self):
        """
        Handles the key renewal process by delegating to KeyManagement.
        """
        try:
            # Use KeyManagement to handle the renewal request
            session_key, public_key = self.key_manager.handle_key_renewal_request(self.server_public_key)
            
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

            # Send key renewal response acknowledgment
            renewal_ack = packageMessage(
                encryptedMessage='',
                signature='',
                nonce=self.nonce_manager.generate_nonce(),
                timestamp=self.nonce_manager.get_current_timestamp(),
                type="keyRenewalResponse"
            )
            sendData(self.socket, renewal_ack)
            log_event("Key Renewal", "Sent key renewal acknowledgment to server.")

            with self._lock:
                self.server_public_key = server_new_public_key
                self.session_key = session_key

        except Exception as e:
            log_event("Error", f"Key renewal failed: {e}")
            self.terminate_session()  # Critical failure should terminate session

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
        """
        Terminates the session by notifying the server and cleaning up resources.
        """
        try:
            if self.socket and self.socket.fileno() != -1:
                # Send termination message
                try:
                    termination_message = packageMessage(
                        encryptedMessage='',
                        signature='',
                        nonce=self.nonce_manager.generate_nonce(),
                        timestamp=self.nonce_manager.get_current_timestamp(),
                        type=MessageType.SESSION_TERMINATION  # Use enum instead of string
                    )
                    sendData(self.socket, termination_message)
                    log_event("Session Termination", "Sent termination message to server.")
                except Exception as e:
                    log_event("Warning", f"Could not send termination message: {e}")
        except Exception as e:
            log_error(ErrorCode.SESSION_ERROR, f"Error during session termination: {e}")
        finally:
            # Ensure all resources are cleaned up
            self.stop_listening()
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
            self.session_key = None
            self.server_public_key = None
            self.nonce_manager.cleanup_old_nonces()  # Add cleanup of nonces
            self.certificate = None
            self.server_certificate = None
            log_event("Session Termination", "Session terminated and resources cleaned up.")

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

    def _validate_server_certificate(self):
        """
        Validates the server's certificate including OCSP check.
        
        Raises:
            ValueError: If certificate validation fails
        """
        try:
            if not self.server_certificate:
                raise ValueError("No server certificate available")

            if not hasattr(self, 'tls_config') or not self.tls_config.ca_cert_path:
                raise ValueError("No CA certificate configured")

            # Load CA certificate
            ca_cert = self.key_manager.load_certificate(self.tls_config.ca_cert_path)
            
            # Verify certificate chain
            if not self.key_manager.verify_certificate(self.server_certificate, ca_cert):
                raise ValueError("Server certificate verification failed")
            log_event("Security", "Server certificate chain verified.")

            # Check certificate revocation if enabled
            if self.tls_config.check_ocsp:
                if not self.key_manager.check_certificate_revocation(self.server_certificate, ca_cert):
                    raise ValueError("Server certificate has been revoked")
                log_event("Security", "Server certificate OCSP check passed.")

            # Verify hostname
            if self.tls_config.verify_peer:
                self._verify_hostname(self.destination[0])
                log_event("Security", "Server hostname verified.")

        except Exception as e:
            log_error(ErrorCode.AUTHENTICATION_ERROR, f"Certificate validation failed: {e}")
            raise ValueError(f"Certificate validation failed: {e}")

    def _verify_hostname(self, hostname):
        """
        Verifies the server's hostname against its certificate.
        
        Args:
            hostname (str): The hostname to verify
            
        Raises:
            ValueError: If hostname verification fails
        """
        try:
            # Get the Subject Alternative Names extension
            san_extension = self.server_certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            san_names = san_extension.value.get_values_for_type(x509.DNSName)
            
            # Check if hostname matches any SAN
            if hostname not in san_names:
                raise ValueError(f"Hostname {hostname} doesn't match certificate SANs")
            
        except x509.ExtensionNotFound:
            # Fall back to Common Name in Subject if no SAN extension
            common_name = self.server_certificate.subject.get_attributes_for_oid(
                x509.NameOID.COMMON_NAME
            )[0].value
            
            if hostname != common_name:
                raise ValueError(f"Hostname {hostname} doesn't match certificate CN")

    def process_server_message(self, message_data: dict):
        """
        Process messages received from the server.
        
        Args:
            message_data (dict): The parsed message data from the server
        """
        try:
            if not self.is_connected():
                log_error(ErrorCode.STATE_ERROR, "Not connected to server")
                return
            
            if not self.session_key:
                log_error(ErrorCode.STATE_ERROR, "No active session")
                return
            
            if len(str(message_data)) > MAX_MESSAGE_SIZE:
                log_error(ErrorCode.VALIDATION_ERROR, "Message exceeds maximum size")
                return
            
            sequence = message_data.get('sequence')
            if not self.sequence_manager.validate_sequence(sequence, message_data.get('sender_id')):
                log_error(ErrorCode.VALIDATION_ERROR, "Invalid message sequence")
                return
            
            message_type = message_data.get('type')
            
            if message_type == MessageType.ACKNOWLEDGE.value:
                log_event("Message", "Server acknowledged message receipt")
                # Message was received successfully, now we can expect a response
                
            elif message_type == MessageType.SERVER_RESPONSE.value:
                # Verify signature before processing
                signature = message_data.get('signature')
                if not self.key_manager.verify_signature(
                    self.server_public_key,
                    message_data['encryptedMessage'].encode(),
                    bytes.fromhex(signature)
                ):
                    log_error(ErrorCode.SECURITY_ERROR, "Invalid message signature")
                    return
                
                try:
                    # Decrypt and process server's response
                    encrypted_msg = bytes.fromhex(message_data.get('encryptedMessage', ''))
                    iv = bytes.fromhex(message_data.get('iv', ''))
                    tag = bytes.fromhex(message_data.get('tag', ''))
                    
                    # Create SecureMessage object
                    secure_msg = SecureMessage(
                        encrypted_message=encrypted_msg,
                        iv=iv,
                        tag=tag
                    )
                    
                    # Decrypt the message
                    decrypted_message = Crypto.decrypt(secure_msg, self.session_key)
                    log_event("Message", f"Received server response: {decrypted_message}")
                    
                    # Handle the server's response (e.g., trigger callbacks, update UI, etc.)
                    self._handle_server_response(decrypted_message)
                    
                except Exception as e:
                    log_error(ErrorCode.ENCRYPTION_ERROR, f"Failed to process server response: {e}")
            
            elif message_type == MessageType.ERROR.value:
                error_message = message_data.get('encryptedMessage', 'Unknown error')
                log_error(ErrorCode.SERVER_ERROR, f"Server error: {error_message}")
                # Handle error condition appropriately
                
            elif message_type == MessageType.KEY_RENEWAL_RESPONSE.value:
                # Handle key renewal response
                try:
                    new_server_public_key = message_data.get('encryptedMessage')
                    if not new_server_public_key:
                        raise ValueError("Missing server public key in renewal response")
                        
                    # Update server's public key
                    self.server_public_key = serialization.load_pem_public_key(
                        new_server_public_key.encode(),
                        backend=default_backend()
                    )
                    
                    # Derive new session key
                    context = b"session key derivation"
                    self.session_key = Crypto.derive_session_key(
                        self.server_public_key,
                        self.private_key,
                        context
                    )
                    
                    log_event("Key Management", "Key renewal completed successfully")
                    
                except Exception as e:
                    log_error(ErrorCode.KEY_MANAGEMENT_ERROR, f"Failed to process key renewal response: {e}")
                    self.terminate_session()
                    
            elif message_type == MessageType.SESSION_TERMINATION.value:
                log_event("Connection", "Received session termination from server")
                self.terminate_session()
                
            else:
                log_error(ErrorCode.VALIDATION_ERROR, f"Unknown message type from server: {message_type}")
                
        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Error processing server message: {e}")

    def _handle_server_response(self, message: str):
        """Handle the decrypted response from the server."""
        try:
            with self._lock:  # Add lock for thread safety
                if hasattr(self, 'message_handler') and self.message_handler:
                    self.message_handler(message)
            
        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Error handling server response: {e}")
