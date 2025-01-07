import server.serverMain
import client.clientMain
import time
import logging
from config.security_config import TLSConfig
from pathlib import Path
import socket
from Communications import MessageType

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def server_message_handler(client_id: str, message: str):
    """Handler for messages received by the server"""
    logging.info(f"Server received message from client {client_id}: {message}")

# For testing, let's disable TLS verification
client_tls_config = TLSConfig(
    enabled=False  # Disable TLS for initial testing
)

server_tls_config = TLSConfig(
    enabled=False  # Disable TLS for initial testing
)

# Create instances with TLS config
denemeclient = None
denemeserver = None

try:
    denemeclient = client.clientMain.Client()
    denemeclient.tls_config = client_tls_config

    denemeserver = server.serverMain.Server("127.0.0.1", 12345, tls_config=server_tls_config)
    denemeserver.set_message_handler(server_message_handler)

    logging.info("Starting server...")
    denemeserver.start()
    time.sleep(0.1)  # Give server time to start

    logging.info("Attempting to establish secure session...")
    if not denemeclient.establish_secure_session(("127.0.0.1", 12345)):
        raise RuntimeError("Failed to establish secure session")
    
    logging.info("Secure session established")
    
    # Start listening for messages
    denemeclient.start_listening()
    logging.info("Started listening for messages")
    
    # Send test message
    logging.info("Sending test message...")
    if not denemeclient.send_message("ceza sahasi"):
        raise RuntimeError("Failed to send message")
    
    logging.info("Message sent: ceza sahasi")
    time.sleep(0.1)  # Wait for server response
    
    # Send server response
    client_ids = denemeserver.get_client_ids()
    if not client_ids:
        raise RuntimeError("No connected clients found")
        
    for client_id in client_ids:
        if not denemeserver.send_message(client_id, "sago pahasi"):
            raise RuntimeError(f"Failed to send response to client {client_id}")
        time.sleep(0.1)  # Wait for message exchange to complete
    
    # Wait for message exchange to complete
    time.sleep(0.2)

except Exception as e:
    logging.error(f"Test failed with error: {e}")
    raise

finally:
    try:
        # Now we can shutdown
        if denemeclient:
            denemeclient.shutdown()
        if denemeserver:
            denemeserver.shutdown()
    except Exception as e:
        logging.error(f"Shutdown failed: {e}")

