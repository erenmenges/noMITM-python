import server.serverMain
import client.clientMain
import time
import logging
from config.security_config import TLSConfig
from pathlib import Path

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
denemeclient = client.clientMain.Client()
denemeclient.tls_config = client_tls_config

denemeserver = server.serverMain.Server("127.0.0.1", 12345, tls_config=server_tls_config)
# Set message handler for server using proper method
denemeserver.set_message_handler(server_message_handler)

logging.info("Starting server...")
denemeserver.start()
time.sleep(1)  # Give server time to start

logging.info("Attempting to establish secure session...")
success = denemeclient.establish_secure_session(("127.0.0.1", 12345))
if success:
    logging.info("Secure session established")
    
    # Start client's message listener
    denemeclient.start_listening()
    time.sleep(1)  # Give listener time to start
    
    logging.info("Sending test message...")
    test_message = "ceza sahasi"
    if denemeclient.send_message(test_message):
        logging.info(f"Message sent: {test_message}")
else:
    logging.error("Failed to establish secure session")

# Keep the program running to see the interaction

time.sleep(1)  # Give server time to clean up

for i in denemeserver.get_client_ids():
    denemeserver.send_response_message(i, "sago pahasi")

denemeclient.stop_listening()
denemeclient.terminate_session() 

