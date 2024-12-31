from Communications import packageMessage, parseMessage, sendData, receiveData
from Crypto import Crypto, SecureMessage
from KeyManagement import KeyManagement
from Utils import NonceManager, log_event
import threading
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

class Server:
    def __init__(self, host="0.0.0.0", port=8080):
        # Initialize key management and nonce manager
        self.key_manager = KeyManagement()
        self.nonce_manager = NonceManager()
        self.session_key = None
        self.listening = False
        self.listen_thread = None
        self.host = host
        self.port = port
        self.client_address = None  # To keep track of client address

        # Schedule automated key renewal every 3600 seconds (1 hour)
        renewal_interval = 3600
        self.key_manager.schedule_key_renewal(renewal_interval)

    def listen(self):
        """
        Starts the server to listen for incoming connections and messages.
        """
        if self.listening:
            log_event("Error", "Server is already listening.")
            return

        self.listening = True
        self.listen_thread = threading.Thread(target=self.listen_for_clients)
        self.listen_thread.daemon = True
        self.listen_thread.start()
        log_event("Server", f"Server started listening on {self.host}:{self.port}.")

    def listen_for_clients(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.host, self.port))
            s.listen()
            while self.listening:
                try:
                    conn, addr = s.accept()
                    self.client_address = addr
                    log_event("Connection", f"Connection established with {addr}.")
                    threading.Thread(target=self.handle_client, args=(conn, addr)).start()
                except Exception as e:
                    log_event("Error", f"Failed to accept connection: {e}")

    def handle_client(self, conn, addr):
        with conn:
            try:
                # Receive the client's public key
                client_public_pem = conn.recv(2048)
                log_event("Key Exchange", "Received client's public key.")

                # Generate the server's key pair
                server_public_pem, server_private_pem = Crypto.generate_key_pair()
                log_event("Key Generation", "Server key pair generated.")

                # Send the server's public key to the client
                conn.sendall(server_public_pem)
                log_event("Key Exchange", "Sent server's public key to client.")

                # Load the client's public key
                client_public_key = serialization.load_pem_public_key(
                    client_public_pem,
                    backend=default_backend()
                )
                log_event("Key Exchange", "Client public key loaded successfully.")

                # Load the server's private key
                server_private_key = serialization.load_pem_private_key(
                    server_private_pem,
                    password=None,
                    backend=default_backend()
                )
                log_event("Key Management", "Server private key loaded successfully.")

                # Derive the shared session key using ECDH
                context = b"session key derivation"
                self.session_key = Crypto.derive_session_key(client_public_key, server_private_key, context)
                log_event("Session", "Session key derived successfully.")

                # Proceed to handle encrypted messages
                while True:
                    received_package = conn.recv(4096)
                    if not received_package:
                        break

                    parsed_message = parseMessage(received_package.decode('utf-8'))
                    log_event("Network", "Message received from client.")

                    msg_type = parsed_message.get("type", "data")

                    if msg_type == "acknowledge":
                        log_event("Network", "Acknowledgment received from client.")
                        continue

                    elif msg_type == "keyRenewalRequest":
                        # {{ edit_1 }} Handle key renewal request
                        log_event("Key Renewal", "Received key renewal request from client.")
                        self.handle_key_renewal_request(conn)
                        continue

                    elif msg_type == "sessionTermination":
                        # {{ edit_2 }} Handle session termination request
                        log_event("Session Termination", "Received session termination request from client.")
                        self.terminate_session(conn, addr)
                        break

                    elif msg_type == "data":
                        # Validate nonce and timestamp
                        nonce = parsed_message['nonce']
                        timestamp = parsed_message['timestamp']
                        if not self.nonce_manager.validate_nonce(nonce):
                            log_event("Security", "Invalid nonce detected!")
                            continue
                        if not self.nonce_manager.validate_timestamp(timestamp):
                            log_event("Security", "Invalid timestamp detected!")
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

                        # Send acknowledgment to client
                        acknowledge_package = packageMessage(
                            encryptedMessage='',
                            signature='',
                            nonce=self.nonce_manager.generate_nonce(),
                            timestamp=self.nonce_manager.get_current_timestamp(),
                            type="acknowledge"
                        )
                        sendData(addr, acknowledge_package)
                        log_event("Network", "Acknowledgment sent to client.")

                        # Server sends its own message to client
                        self.send_message(conn, addr, "Hello from server!")

            except Exception as e:
                log_event("Error", f"Failed to process incoming message: {e}")

        def handle_key_renewal_request(self, conn):
            """
            Handles the key renewal process by generating a new key pair and sending the new public key to the client.
            """
            try:
                # Generate new key pair
                new_public_pem, new_private_pem = Crypto.generate_key_pair()
                log_event("Key Renewal", "Generated new key pair for renewal.")

                # Send the new public key to the client
                conn.sendall(new_public_pem)
                log_event("Key Renewal", "Sent new public key to client.")

                # Load the new private key
                new_private_key = serialization.load_pem_private_key(
                    new_private_pem,
                    password=None,
                    backend=default_backend()
                )
                log_event("Key Renewal", "Loaded new private key.")

                # Assume client sends its new public key in response
                client_new_public_pem = conn.recv(2048)
                client_new_public_key = serialization.load_pem_public_key(
                    client_new_public_pem,
                    backend=default_backend()
                )
                log_event("Key Renewal", "Received new public key from client.")

                # Derive the new session key
                context = b"session key derivation"
                self.session_key = Crypto.derive_session_key(client_new_public_key, new_private_key, context)
                log_event("Session", "New session key derived successfully.")

                # Send key renewal response acknowledgment
                renewal_ack = packageMessage(
                    encryptedMessage='',
                    signature='',
                    nonce=self.nonce_manager.generate_nonce(),
                    timestamp=self.nonce_manager.get_current_timestamp(),
                    type="keyRenewalResponse"
                )
                sendData(self.client_address, renewal_ack)
                log_event("Key Renewal", "Sent key renewal acknowledgment to client.")

            except Exception as e:
                log_event("Error", f"Key renewal failed: {e}")

        def request_key_renewal(self, conn, addr):
            """
            Initiates the key renewal process by sending a key renewal request to the client.
            """
            try:
                # Send key renewal request
                key_renewal_request = packageMessage(
                    encryptedMessage='',
                    signature='',
                    nonce=self.nonce_manager.generate_nonce(),
                    timestamp=self.nonce_manager.get_current_timestamp(),
                    type="keyRenewalRequest"
                )
                sendData(addr, key_renewal_request)
                log_event("Key Renewal", "Sent key renewal request to client.")
            except Exception as e:
                log_event("Error", f"Failed to send key renewal request: {e}")

        def terminate_session(self, conn, addr):
            """
            Terminates the session by notifying the client and closing the connection.
            """
            try:
                termination_message = packageMessage(
                    encryptedMessage='',
                    signature='',
                    nonce=self.nonce_manager.generate_nonce(),
                    timestamp=self.nonce_manager.get_current_timestamp(),
                    type="sessionTermination"
                )
                sendData(addr, termination_message)
                log_event("Session Termination", "Sent session termination message to client.")
            except Exception as e:
                log_event("Error", f"Failed to send session termination message: {e}")
            finally:
                conn.close()
                log_event("Session Termination", "Session terminated and connection closed.")

    def send_message(self, conn, addr, message):
        """
        Sends a message to the connected client.
        
        Args:
            message (str): The message to send.
        """
        if not self.session_key:
            log_event("Error", "Session not established. Cannot send message.")
            return

        nonce = self.nonce_manager.generate_nonce()  # Generate a unique nonce
        timestamp = self.nonce_manager.get_current_timestamp()  # Get current timestamp

        # Encrypt the message using the session key
        iv, encrypted_message = Crypto.aes_encrypt(message.encode('utf-8'), self.session_key)

        # Create a hash of the encrypted message to ensure integrity
        message_hash = Crypto.hash(encrypted_message)
        # Package the encrypted message with metadata into a JSON structure
        message_package = packageMessage(
            encryptedMessage=encrypted_message.hex(),
            signature=message_hash.hex(),
            nonce=nonce,
            timestamp=timestamp,
            type="serverMessage",
            iv=iv.hex()
        )
        log_event("Message Packaging", "Server message packaged successfully.")

        try:
            # Send the packaged message to the client
            sendData(addr, message_package)
            log_event("Network", "Server message sent to client.")
        except Exception as e:
            # Log any errors encountered during message sending
            log_event("Error", f"Failed to send server message: {e}")

    def close_session(self):
        """
        Closes the server's listening thread and cleans up the session.
        """
        if not self.listening:
            log_event("Error", "Server is not currently listening.")
            return

        self.listening = False
        if self.listen_thread and self.listen_thread.is_alive():
            self.listen_thread.join()
        log_event("Session", "Server session closed successfully.")
