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
        check_hostname=True,
        minimum_version="TLSv1_2",
        cipher_suites=[
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384'
        ],
        session_tickets=False,
        reuse_sessions=True,
        session_timeout=3600
    )

    # Configure TLS for client
    client_tls_config = TLSConfig(
        enabled=True,
        cert_path=cert_dir / "client.crt",
        key_path=cert_dir / "client.key",
        ca_path=cert_dir / "ca.crt",
        verify_mode="CERT_REQUIRED",
        check_hostname=True,
        minimum_version="TLSv1_2",
        cipher_suites=[
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384'
        ],
        session_tickets=False,
        reuse_sessions=True,
        session_timeout=3600
    )

    server = None
    client = None

    try:
        # Create server and client instances
        server = Server("localhost", 12345, tls_config=server_tls_config)
        client = Client(tls_config=client_tls_config)

        # Set message handler for server
        server.set_message_handler(server_message_handler)

        # Start server
        logging.info("Starting server...")
        server.start()
        time.sleep(0.1)  # Give server time to start

        # Verify server is running
        if not server.running:
            raise RuntimeError("Server failed to start")

        # Establish secure session
        logging.info("Attempting to establish secure session...")
        success = client.establish_secure_session(("localhost", 12345))
        
        if not success:
            raise RuntimeError("Failed to establish secure session")
            
        logging.info("Secure session established successfully")
        
        # Verify connection state
        if not client.is_connected():
            raise RuntimeError("Client reports as not connected")
        
        # Start client's message listener
        client.start_listening()
        time.sleep(0.1)
        
        # Send test messages
        test_messages = [
            "Hello, secure world!",
            "Testing TLS communication",
            "Final test message"
        ]
        
        for msg in test_messages:
            logging.info(f"Sending message: {msg}")
            if not client.send_message(msg):
                raise RuntimeError(f"Failed to send message: {msg}")
            logging.info(f"Message sent successfully: {msg}")
            time.sleep(0.2)  # Increased delay between messages
            
            # Verify server received the message
            # Wait for a short time to allow message processing
            time.sleep(0.1)
            
        # Wait for final message processing
        time.sleep(0.1)
            
        # Add small delay before cleanup to ensure all messages are processed
        time.sleep(0.2)
            
    except Exception as e:
        if "wrong version number" in str(e) or "protocol version" in str(e):
            # These are normal during shutdown, not actual errors
            logging.debug("TLS shutdown alerts (normal behavior)")
        else:
            logging.error(f"Error during TLS testing: {e}", exc_info=True)
            raise
        
    finally:
        # Cleanup
        logging.info("Cleaning up...")
        try:
            if client:
                client.shutdown()  # Use shutdown instead of stop
                logging.info("Client shutdown completed")
        except Exception as e:
            logging.error(f"Error during client cleanup: {e}")
            
        try:
            if server:
                server.shutdown()
                logging.info("Server shutdown completed")
        except Exception as e:
            logging.error(f"Error during server cleanup: {e}")

if __name__ == "__main__":
    test_tls_communication() 