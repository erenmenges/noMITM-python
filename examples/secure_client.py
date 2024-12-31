from client.clientMain import Client
from config.security_config import SecurityConfig, TLSConfig

# Create TLS configuration
tls_config = TLSConfig(
    enabled=True,
    cert_path="/path/to/client.crt",
    key_path="/path/to/client.key",
    ca_cert_path="/path/to/ca.crt",
    verify_peer=True,
    check_ocsp=True
)

# Create client
client = Client()
client.tls_config = tls_config

# Connect to server
client.establish_session(('localhost', 5000)) 