from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
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
    """Configuration for TLS settings."""
    enabled: bool = False
    cert_path: Optional[Path] = None
    key_path: Optional[Path] = None
    ca_path: Optional[Path] = None
    verify_mode: str = "NONE"
    check_hostname: bool = False
    ciphers: str = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384"
    protocols: tuple = field(default_factory=lambda: ("TLSv1.2", "TLSv1.3"))
    options: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Convert string paths to Path objects if they're strings."""
        if isinstance(self.cert_path, str):
            self.cert_path = Path(self.cert_path)
        if isinstance(self.key_path, str):
            self.key_path = Path(self.key_path)
        if isinstance(self.ca_path, str):
            self.ca_path = Path(self.ca_path)

@dataclass
class SecurityConfig:
    tls: TLSConfig = field(default_factory=TLSConfig)
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