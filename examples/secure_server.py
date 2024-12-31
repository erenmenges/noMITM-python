from server.serverMain import Server
from config.security_config import SecurityConfig, TLSConfig, CertificateConfig

# Create certificate configuration
cert_config = CertificateConfig(
    cert_path="/path/to/server.crt",
    key_path="/path/to/server.key",
    ca_cert_path="/path/to/ca.crt",
    require_client_cert=True,
    allowed_subjects=["client1", "client2"]
)

# Create TLS configuration
tls_config = TLSConfig(
    enabled=True,
    cert_config=cert_config,
    verify_peer=True,
    check_ocsp=True
)

# Create security configuration
security_config = SecurityConfig(
    tls=tls_config,
    enable_mutual_tls=True,
    cert_revocation_check=True
)

# Validate certificate paths
security_config.validate_paths()

# Create and start server
server = Server(
    host='localhost',
    port=5000,
    tls_config=tls_config
)
server.start() 