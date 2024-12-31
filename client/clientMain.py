import threading
import socket
from Communications import packageMessage, parseMessage, sendData, receiveData
from Crypto import Crypto, SecureMessage
from KeyManagement import KeyManagement
from Utils import NonceManager, log_event
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class Client:
    def __init__(self):
        # Initialize key management and nonce manager
        self.key_manager = KeyManagement()
        self.nonce_manager = NonceManager()
        self.session_key = None
        self.listening = False
        self.listen_thread = None
        self.destination = None
        self.private_key = None  # Add attribute to store client's private key
        self.public_key = None   # Add attribute to store client's public key

        # Schedule automated key renewal every 3600 seconds (1 hour)
        renewal_interval = 3600
        self.key_manager.schedule_key_renewal(renewal_interval)

    def establish_session(self, destination):
        """
        Establishes a secure session with the server.
        
        Args:
            destination (tuple): A tuple containing the server's IP and port.
        """
        self.destination = destination

        # Generate the client's key pair for secure communication
        public_pem, private_pem = Crypto.generate_key_pair()
        log_event("Key Generation", "Client key pair generated.")

        # Connect to the server
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.connect(destination)
                log_event("Network", f"Connected to server at {destination}.")

                # Send the client's public key to the server
                s.sendall(public_pem)
                log_event("Key Exchange", "Sent public key to server.")

                # Receive the server's public key
                server_public_pem = s.recv(2048)
                log_event("Key Exchange", "Received public key from server.")

            except Exception as e:
                log_event("Error", f"Failed to establish connection: {e}")
                return

        # Load the server's public key
        try:
            server_public_key = serialization.load_pem_public_key(
                server_public_pem,
                backend=default_backend()
            )
            log_event("Key Exchange", "Server public key loaded successfully.")
        except Exception as e:
            log_event("Error", f"Failed to load server public key: {e}")
            return

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

    def send_message(self, message):
        """
        Sends a message to the server.
        
        Args:
            message (str): The message to send.
        """
        if not self.session_key:
            log_event("Error", "Session not established. Cannot send message.")
            return

        nonce = self.nonce_manager.generate_nonce()  # Generate a unique nonce
        timestamp = self.nonce_manager.get_current_timestamp()  # Get the current timestamp

        # Encrypt the message using AES-GCM
        secure_msg = Crypto.encrypt(message.encode('utf-8'), self.session_key)

        # Serialize the secure message
        msg_dict = secure_msg.to_dict()

        # Package the message for transmission
        message_package = packageMessage(
            encryptedMessage=msg_dict['ciphertext'].hex(),
            nonce=msg_dict['nonce'].hex(),
            tag=msg_dict['tag'].hex(),
            timestamp=timestamp,
            type="data",
            iv=msg_dict['nonce'].hex()  # Using nonce as IV for AES-GCM
        )
        log_event("Message Packaging", "Message packaged successfully.")

        # Prepare the message for signing
        message_bytes = message_package.encode('utf-8')

        # Sign the message
        signature = self.key_manager.sign_message(self.private_key, message_bytes)

        # Update the message package with the signature
        message_package_dict = {
            "encryptedMessage": msg_dict['ciphertext'].hex(),
            "nonce": msg_dict['nonce'].hex(),
            "tag": msg_dict['tag'].hex(),
            "timestamp": timestamp,
            "type": "data",
            "iv": msg_dict['nonce'].hex(),  # Using nonce as IV for AES-GCM
            "signature": signature.hex()
        }
        message_package_signed = packageMessage(**message_package_dict)
        log_event("Message Signing", "Message signed successfully.")

        try:
            # Send the signed message to the server
            sendData(self.destination, message_package_signed)
            log_event("Network", "Message sent to the server.")
        except Exception as e:
            # Log any errors encountered during message sending
            log_event("Error", f"Failed to send message: {e}")

    def receive_messages(self):
        """
        Listens for incoming messages from the server.
        """
        if not self.session_key:
            log_event("Error", "Session not established. Cannot receive messages.")
            return

        while self.listening:
            try:
                received_package = receiveData()
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
                    ciphertext = bytes.fromhex(parsed_message['encryptedMessage']) + bytes.fromhex(parsed_message['tag'])
                    decrypted_message = Crypto.decrypt(
                        SecureMessage(
                            ciphertext=ciphertext[:-16],
                            nonce=bytes.fromhex(parsed_message['nonce']),
                            tag=ciphertext[-16:],
                            version=1,
                            salt=b''  # Assuming salt is managed elsewhere
                        ),
                        self.session_key
                    )

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
            sendData(self.destination, new_public_pem)
            log_event("Key Renewal", "Sent new public key to server.")

            # Load the new private key
            new_private_key = serialization.load_pem_private_key(
                new_private_pem,
                password=None,
                backend=default_backend()
            )
            log_event("Key Renewal", "Loaded new private key.")

            # Assume server sends its new public key in response
            server_new_public_pem = receiveData()
            server_new_public_key = serialization.load_pem_public_key(
                server_new_public_pem,
                backend=default_backend()
            )
            log_event("Key Renewal", "Received new public key from server.")

            # Derive the new session key
            context = b"session key derivation"
            self.session_key = Crypto.derive_session_key(server_new_public_key, new_private_key, context)
            log_event("Session", "New session key derived successfully.")

            # Send key renewal response acknowledgment
            renewal_ack = packageMessage(
                encryptedMessage='',
                signature='',
                nonce=self.nonce_manager.generate_nonce(),
                timestamp=self.nonce_manager.get_current_timestamp(),
                type="keyRenewalResponse"
            )
            sendData(self.destination, renewal_ack)
            log_event("Key Renewal", "Sent key renewal acknowledgment to server.")

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
            sendData(self.destination, client_new_public_pem)
            log_event("Key Renewal", "Sent new public key to server.")

            # Load the new private key
            new_private_key = serialization.load_pem_private_key(
                client_new_private_pem,
                password=None,
                backend=default_backend()
            )
            log_event("Key Renewal", "Loaded new private key.")

            # Receive the server's new public key
            server_new_public_pem = receiveData()
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

    def terminate_session(self):
        """
        Terminates the session by notifying the server and cleaning up resources.
        """
        try:
            # Send session termination message to server
            termination_message = packageMessage(
                encryptedMessage='',
                signature='',
                nonce=self.nonce_manager.generate_nonce(),
                timestamp=self.nonce_manager.get_current_timestamp(),
                type="sessionTermination"
            )
            sendData(self.destination, termination_message)
            log_event("Session Termination", "Sent session termination message to server.")
        except Exception as e:
            log_event("Error", f"Failed to send session termination message: {e}")
        finally:
            self.stop_listening()
            self.session_key = None
            log_event("Session Termination", "Session terminated successfully.")

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
