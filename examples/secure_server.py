from server.serverMain import Server
from config.security_config import SecurityConfig, TLSConfig
import os
from pathlib import Path

def validate_cert_path(path: str) -> str:
    """Validate certificate path exists and is readable"""
    cert_path = os.getenv(path) or path
    if not Path(cert_path).is_file():
        raise ValueError(f"Certificate file not found: {cert_path}")
    return cert_path

# Create TLS configuration with validated paths
tls_config = TLSConfig(
    enabled=True,
    cert_path=validate_cert_path(os.getenv("SERVER_CERT_PATH", "/path/to/server.crt")),
    key_path=validate_cert_path(os.getenv("SERVER_KEY_PATH", "/path/to/server.key")),
    ca_cert_path=validate_cert_path(os.getenv("CA_CERT_PATH", "/path/to/ca.crt")),
    verify_peer=True,
    check_ocsp=True
)

# Create security configuration
security_config = SecurityConfig(
    tls=tls_config,
    enable_mutual_tls=True,
    cert_revocation_check=True
)

# Create and start server
server = Server(
    host='localhost',
    port=5000,
    tls_config=tls_config
)
server.start() 