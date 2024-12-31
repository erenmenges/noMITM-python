from Communications import packageMessage, parseMessage, sendData, receiveData
from Crypto import Crypto
from KeyManagement import KeyManagement
from Utils import NonceManager, log_event
import threading

class Main:
    @staticmethod
    def establish_session_and_send_message(message, destination):
        # Initialize key management and nonce manager
        key_manager = KeyManagement()
        nonce_manager = NonceManager()

        # Schedule automated key renewal every 3600 seconds (1 hour)
        renewal_interval = 3600
        key_manager.schedule_key_renewal(renewal_interval)

        # Generate the initial key pair for secure communication
        private_key, public_key = key_manager.initiate_key_renewal()
        log_event("Key Generation", "Initial key pair generated.")

        # Prepare a message for secure transmission
        nonce = nonce_manager.generate_nonce()  # Generate a unique nonce
        timestamp = nonce_manager.get_current_timestamp()  # Get the current timestamp

        # Simulate peer key pair generation for session key derivation
        peer_private_key, peer_public_key = Crypto.generate_key_pair()
        # Derive a symmetric session key using the peer's public key and our private key
        session_key = Crypto.derive_session_key(peer_public_key, private_key)
        # Encrypt the message using the derived session key
        iv, encrypted_message = Crypto.aes_encrypt(message.encode('utf-8'), session_key)

        # Create a hash of the encrypted message to ensure integrity
        message_hash = Crypto.hash(encrypted_message)
        # Package the encrypted message with metadata into a JSON structure
        message_package = packageMessage(
            encryptedMessage=encrypted_message.hex(),
            signature=message_hash.hex(),
            nonce=nonce,
            timestamp=timestamp
        )
        log_event("Message Packaging", "Message packaged successfully.")

        try:
            # Send the packaged message to the destination
            sendData(destination, message_package)
            log_event("Network", "Message sent to the destination.")
        except Exception as e:
            # Log any errors encountered during message sending
            log_event("Error", f"Failed to send message: {e}")

        try:
            # Receive a response message from the destination
            received_package = receiveData()
            # Parse the received JSON package into a Python dictionary
            parsed_message = parseMessage(received_package)
            log_event("Network", "Message received and parsed successfully.")

            # Handle key renewal responses
            if parsed_message.get("type") == "keyRenewalResponse":
                log_event("Key Renewal", "Key renewal response received successfully.")
                return

            # Validate the nonce to ensure it's unique and unused
            if not nonce_manager.validate_nonce(parsed_message['nonce']):
                log_event("Security", "Invalid nonce detected!")
                return

            # Validate the timestamp to ensure it's within an acceptable time window
            if not nonce_manager.validate_timestamp(parsed_message['timestamp']):
                log_event("Security", "Invalid timestamp detected!")
                return

            # Extract the ciphertext from the parsed message and decrypt it
            ciphertext = bytes.fromhex(parsed_message['encryptedMessage'])
            decrypted_message = Crypto.aes_decrypt(iv, ciphertext, session_key)

            # Print the decrypted message to verify successful decryption
            print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")

        except Exception as e:
            # Log any errors encountered during message reception or processing
            log_event("Error", f"Failed to receive or process message: {e}")
