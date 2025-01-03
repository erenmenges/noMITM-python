import os
import time
import logging
from pathlib import Path
from server.serverMain import Server
from client.clientMain import Client
from config.security_config import TLSConfig

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def test_tls_communication():
    """Test TLS communication between client and server."""
    # Certificate paths
    cert_dir = Path("test_certs")
    if not cert_dir.exists():
        raise FileNotFoundError("Test certificates not found. Run generate_test_certs.py first.")

    # Server message handler
    def server_message_handler(client_id: str, message: str):
        logging.info(f"Server received message from client {client_id}: {message}")

    # Configure TLS for server
    server_tls_config = TLSConfig(
        enabled=True,
        cert_path=cert_dir / "server.crt",
        key_path=cert_dir / "server.key",
        ca_path=cert_dir / "ca.crt",
        verify_mode="CERT_REQUIRED",
        check_hostname=True
    )

    # Configure TLS for client
    client_tls_config = TLSConfig(
        enabled=True,
        cert_path=cert_dir / "client.crt",
        key_path=cert_dir / "client.key",
        ca_path=cert_dir / "ca.crt",
        verify_mode="CERT_REQUIRED",
        check_hostname=True
    )

    # Create server and client instances
    server = Server("localhost", 12345, tls_config=server_tls_config)
    client = Client(tls_config=client_tls_config)  # Now we can pass it directly

    try:
        # Set message handler for server
        server.set_message_handler(server_message_handler)

        # Start server
        logging.info("Starting server...")
        server.start()
        time.sleep(1)  # Give server time to start

        # Establish secure session
        logging.info("Attempting to establish secure session...")
        success = client.establish_secure_session(("localhost", 12345))
        
        if success:
            logging.info("Secure session established successfully")
            
            # Start client's message listener
            client.start_listening()
            time.sleep(1)
            
            # Send test messages
            test_messages = [
                "Hello, secure world!",
                "Testing TLS communication",
                "Final test message"
            ]
            
            for msg in test_messages:
                logging.info(f"Sending message: {msg}")
                if client.send_message(msg):
                    logging.info(f"Message sent successfully: {msg}")
                    time.sleep(1)  # Wait for processing
                else:
                    logging.error(f"Failed to send message: {msg}")
            
            # Wait for final message processing
            time.sleep(2)
            
        else:
            logging.error("Failed to establish secure session")
            
    except Exception as e:
        logging.error(f"Error during TLS testing: {e}", exc_info=True)
        
    finally:
        # Cleanup
        logging.info("Cleaning up...")
        try:
            client.stop()
        except:
            pass
        try:
            server.shutdown()
        except:
            pass

if __name__ == "__main__":
    test_tls_communication() 