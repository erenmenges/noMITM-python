from Communications import packageMessage, parseMessage, sendData, receiveData
from Crypto import Crypto
from KeyManagement import KeyManagement
from Utils import NonceManager, log_event
import threading

def main():
    # Initialize key management and nonce manager
    key_manager = KeyManagement()
    nonce_manager = NonceManager()

    # Schedule automated key renewal every 3600 seconds (1 hour)
    renewal_interval = 3600
    key_manager.schedule_key_renewal(renewal_interval)

    # Generate the initial key pair for secure communication
    private_key, public_key = key_manager.initiate_key_renewal()
    log_event("Key Generation", "Initial key pair generated.")

    while True:
        try:
            # Wait for an incoming message
            received_package = receiveData()
            log_event("Network", "Message received.")

            # Parse the received JSON package into a Python dictionary
            parsed_message = parseMessage(received_package)
            log_event("Message Parsing", "Message parsed successfully.")

            # Validate the nonce to ensure it's unique and unused
            if not nonce_manager.validate_nonce(parsed_message['nonce']):
                log_event("Security", "Invalid nonce detected!")
                continue

            # Validate the timestamp to ensure it's within an acceptable time window
            if not nonce_manager.validate_timestamp(parsed_message['timestamp']):
                log_event("Security", "Invalid timestamp detected!")
                continue

            # Handle key renewal requests
            if parsed_message.get("type") == "keyRenewalRequest":
                new_public_key = parsed_message.get("newPublicKey")
                session_key, response_public_key = key_manager.handle_key_renewal_request(new_public_key)

                # Send a key renewal response back to the client
                response_package = packageMessage(
                    encryptedMessage="",  # No encrypted message in key renewal
                    signature="",         # No signature for simplicity
                    nonce=nonce_manager.generate_nonce(),
                    timestamp=nonce_manager.get_current_timestamp()
                )
                sendData(("127.0.0.1", 8080), response_package)
                log_event("Key Renewal", "Key renewal response sent.")
                continue

            # Extract the ciphertext and decrypt it using the derived session key
            ciphertext = bytes.fromhex(parsed_message['encryptedMessage'])
            session_key = Crypto.derive_session_key(public_key, private_key)  # Derive session key
            decrypted_message = Crypto.aes_decrypt(ciphertext[:16], ciphertext[16:], session_key)

            log_event("Decryption", "Message decrypted successfully.")
            print(f"Decrypted Message: {decrypted_message.decode('utf-8')}")

            # Prepare a response message
            response_message = "Message received successfully."
            response_nonce = nonce_manager.generate_nonce()
            response_timestamp = nonce_manager.get_current_timestamp()

            iv, encrypted_response = Crypto.aes_encrypt(response_message.encode('utf-8'), session_key)
            response_hash = Crypto.hash(encrypted_response)

            response_package = packageMessage(
                encryptedMessage=encrypted_response.hex(),
                signature=response_hash.hex(),
                nonce=response_nonce,
                timestamp=response_timestamp
            )

            # Send the response back to the client
            sendData(("127.0.0.1", 8080), response_package)
            log_event("Network", "Response sent to the client.")

        except Exception as e:
            log_event("Error", f"Failed to process incoming message: {e}")

if __name__ == "__main__":
    main()
