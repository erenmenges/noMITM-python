import threading
import socket
from Communications import packageMessage, parseMessage, sendData, receiveData
from Crypto import Crypto, SecureMessage
from KeyManagement import KeyManagement
from Utils import NonceManager, log_event, log_error, ErrorCode, ErrorMessage
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from security.TLSWrapper import TLSWrapper

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

                # If TLS is enabled, wrap the socket
                if hasattr(self, 'tls_config') and self.tls_config.enabled:
                    tls_wrapper = TLSWrapper(self.tls_config)
                    self.socket = tls_wrapper.wrap_socket(
                        self.socket,
                        server_side=False,
                        server_hostname=destination[0]
                    )
                    log_event("Security", "TLS connection established.")

                self.socket.connect(destination)
                log_event("Network", f"Connected to server at {destination}.")

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
                received_package = receiveData(self.socket)  # Pass the connected socket
                if not received_package:
                    continue

                # Parse the received message
                parsed_message = parseMessage(received_package)
                log_event("Network", "Message received from server.")

                msg_type = parsed_message.get("type", "data")

                if msg_type == "acknowledge":
                    log_event("Network", "Acknowledgment received from server.")
                    continue

                elif msg_type == "keyRenewalRequest":
                    # {{ edit_1 }} Handle key renewal request
                    log_event("Key Renewal", "Received key renewal request from server.")
                    self.handle_key_renewal_request()
                    continue

                elif msg_type == "keyRenewalResponse":
                    # {{ edit_2 }} Handle key renewal response
                    log_event("Key Renewal", "Received key renewal response from server.")
                    self.handle_key_renewal_response()
                    continue

                elif msg_type == "sessionTermination":
                    # {{ edit_3 }} Handle session termination request
                    log_event("Session Termination", "Received session termination request from server.")
                    self.terminate_session()
                    break

                elif msg_type == "data":
                    # Validate nonce and timestamp
                    nonce = bytes.fromhex(parsed_message['nonce'])
                    timestamp = parsed_message['timestamp']
                    if not self.nonce_manager.validate_nonce(nonce.decode('utf-8')):
                        log_event("Security", "Invalid nonce detected!")
                        continue
                    if not self.nonce_manager.validate_timestamp(timestamp):
                        log_event("Security", "Invalid timestamp detected!")
                        continue

                    # Verify the message signature before decryption
                    signature_hex = parsed_message.get("signature", "")
                    if not signature_hex:
                        log_event("Security", "No signature found in the message.")
                        continue
                    
                    signature = bytes.fromhex(signature_hex)
                    message_copy = packageMessage(
                        encryptedMessage=parsed_message['encryptedMessage'],
                        nonce=parsed_message['nonce'],
                        tag=parsed_message['tag'],
                        timestamp=parsed_message['timestamp'],
                        type=parsed_message['type'],
                        iv=parsed_message['iv']
                    )
                    signature_valid = self.key_manager.verify_signature(
                        self.server_public_key,  # Assume server_public_key is stored after session establishment
                        message_copy.encode('utf-8'),
                        signature
                    )
                    if not signature_valid:
                        log_event("Security", "Invalid message signature detected!")
                        continue

                    # Decrypt the message
                    secure_msg = SecureMessage.from_dict(parsed_message)
                    decrypted_message = Crypto.decrypt(secure_msg, self.session_key)

                    log_event("Message", f"Decrypted message: {decrypted_message.decode('utf-8')}")
                
            except Exception as e:
                log_event("Error", f"Failed to receive or decrypt message: {e}")

    def handle_key_renewal_request(self):
        """
        Handles the key renewal process by generating a new key pair and sending the new public key to the server.
        """
        try:
            # Generate new key pair
            new_public_pem, new_private_pem = Crypto.generate_key_pair()
            log_event("Key Renewal", "Generated new key pair for renewal.")

            # Send the new public key to the server
            sendData(self.socket, new_public_pem)
            log_event("Key Renewal", "Sent new public key to server.")

            # Load the new private key
            new_private_key = serialization.load_pem_private_key(
                new_private_pem,
                password=None,
                backend=default_backend()
            )
            log_event("Key Renewal", "Loaded new private key.")

            # Assume server sends its new public key in response
            server_new_public_pem = receiveData(self.socket)
            server_new_public_key = serialization.load_pem_public_key(
                server_new_public_pem,
                backend=default_backend()
            )
            log_event("Key Renewal", "Received new public key from server.")

            # Derive the new session key
            context = b"session key derivation"
            new_session_key = Crypto.derive_session_key(server_new_public_key, new_private_key, context)
            log_event("Session", "New session key derived successfully.")

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
                self.private_key = new_private_key
                self.server_public_key = server_new_public_key
                self.session_key = new_session_key

        except Exception as e:
            log_event("Error", f"Key renewal failed: {e}")

    def handle_key_renewal_response(self):
        """
        Handles the key renewal response from the server by deriving the new session key.
        """
        try:
            # Assume client sends its new public key in response
            client_new_public_pem, client_new_private_pem = Crypto.generate_key_pair()
            log_event("Key Renewal", "Generated new key pair for renewal.")

            # Send the new public key to the server
            sendData(self.socket, client_new_public_pem)
            log_event("Key Renewal", "Sent new public key to server.")

            # Load the new private key
            new_private_key = serialization.load_pem_private_key(
                client_new_private_pem,
                password=None,
                backend=default_backend()
            )
            log_event("Key Renewal", "Loaded new private key.")

            # Receive the server's new public key
            server_new_public_pem = receiveData(self.socket)
            server_new_public_key = serialization.load_pem_public_key(
                server_new_public_pem,
                backend=default_backend()
            )
            log_event("Key Renewal", "Received new public key from server.")

            # Derive the new session key
            context = b"session key derivation"
            self.session_key = Crypto.derive_session_key(server_new_public_key, new_private_key, context)
            log_event("Session", "New session key derived successfully.")

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
