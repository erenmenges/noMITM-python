from dataclasses import dataclass
from typing import Optional, List
from pathlib import Path

@dataclass
class CertificateConfig:
    """Configuration for certificate handling"""
    cert_path: str
    key_path: str
    ca_cert_path: str
    crl_path: Optional[str] = None
    allowed_subjects: Optional[List[str]] = None
    verify_depth: int = 3
    require_client_cert: bool = False

@dataclass
class TLSConfig:
    enabled: bool = False
    cert_config: Optional[CertificateConfig] = None
    verify_peer: bool = True
    check_ocsp: bool = True
    ocsp_timeout: int = 10
    min_tls_version: str = "TLS1_3"
    cipher_suites: list[str] = None

    def __post_init__(self):
        if self.enabled and not self.cert_config:
            raise ValueError("Certificate configuration must be provided when TLS is enabled")
        
        if self.cipher_suites is None:
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
    
    def validate_paths(self):
        """Validate that all configured certificate paths exist"""
        if self.tls.enabled and self.tls.cert_config:
            paths = [
                self.tls.cert_config.cert_path,
                self.tls.cert_config.key_path,
                self.tls.cert_config.ca_cert_path
            ]
            if self.tls.cert_config.crl_path:
                paths.append(self.tls.cert_config.crl_path)
                
            for path in paths:
                if not Path(path).is_file():
                    raise ValueError(f"Certificate file not found: {path}") 