from dataclasses import dataclass
from typing import Optional

@dataclass
class TLSConfig:
    enabled: bool = False
    cert_path: Optional[str] = None
    key_path: Optional[str] = None
    ca_cert_path: Optional[str] = None
    verify_peer: bool = True
    check_ocsp: bool = True
    ocsp_timeout: int = 10
    min_tls_version: str = "TLS1_3"  # TLS1_2 or TLS1_3
    cipher_suites: list[str] = None

    def __post_init__(self):
        if self.enabled and (not self.cert_path or not self.key_path):
            raise ValueError("Certificate and key paths must be provided when TLS is enabled")
        
        if self.cipher_suites is None:
            # Default to secure cipher suites
            self.cipher_suites = [
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_AES_128_GCM_SHA256',
            ]

@dataclass
class SecurityConfig:
    tls: TLSConfig = TLSConfig()
    connection_timeout: int = 30
    enable_mutual_tls: bool = False
    cert_revocation_check: bool = True
    cert_validation_depth: int = 3 