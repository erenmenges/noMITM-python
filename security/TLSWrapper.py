import ssl
import socket
from typing import Optional, Tuple
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from config.security_config import TLSConfig
from KeyManagement import OCSPValidator
from Utils import log_event, log_error, ErrorCode, CommunicationError

class TLSWrapper:
    def __init__(self, config: TLSConfig, client_mode: bool = False):
        self.config = config
        self.client_mode = client_mode  # <-- New flag to indicate client use
        # Set default attributes if not provided by config
        self.check_ocsp = getattr(config, "check_ocsp", False)
        self.minimum_version = getattr(config, "minimum_version", "TLSv1_2")
        self.ca_path = getattr(config, "ca_path", None) or getattr(config, "ca_cert_path", None)
        self.verify_peer = getattr(config, "verify_peer", None)
        if self.verify_peer is None:
            # Derive verify_peer from the verify_mode if not explicitly set
            self.verify_peer = config.verify_mode == "CERT_REQUIRED"

        self.ocsp_validator = OCSPValidator() if self.check_ocsp else None
        self._ssl_context = self._create_ssl_context()
        log_event("TLSWrapper", f"Initialized TLSWrapper with config: minimum_version={self.minimum_version}, verify_peer={self.verify_peer}, ca_path={self.ca_path}, check_ocsp={self.check_ocsp}")

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context based on configuration."""
        log_event("TLSWrapper", f"Creating SSL context with configured minimum version: {self.minimum_version}")
        if self.client_mode:
            # For client mode, use PROTOCOL_TLS_CLIENT
            if self.minimum_version in ["TLS1_3", "TLSv1_3"]:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.TLSv1_3
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            # For server mode, use PROTOCOL_TLS_SERVER
            if self.minimum_version in ["TLS1_3", "TLSv1_3"]:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_3
            else:
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Set cipher suites
        context.set_ciphers(':'.join(self.config.cipher_suites))
        log_event("TLSWrapper", f"Using cipher suites: {':'.join(self.config.cipher_suites)}")

        # Load certificates (only required if the certificate paths are provided)
        try:
            if self.client_mode:
                if self.config.cert_path and self.config.key_path:
                    log_event("TLSWrapper", f"Loading client certificate from {self.config.cert_path} and key from {self.config.key_path}")
                    context.load_cert_chain(
                        certfile=self.config.cert_path,
                        keyfile=self.config.key_path
                    )
                    log_event("TLSWrapper", "Loaded client certificate and key successfully.")
                else:
                    log_event("TLSWrapper", "No client certificate provided, skipping client cert load.")
            else:
                log_event("TLSWrapper", f"Loading server certificate from {self.config.cert_path} and key from {self.config.key_path}")
                context.load_cert_chain(
                    certfile=self.config.cert_path,
                    keyfile=self.config.key_path
                )
                log_event("TLSWrapper", "Loaded server certificate and key successfully.")
        except Exception as e:
            log_error(ErrorCode.CERTIFICATE_ERROR, f"Failed to load certificate: {e}")
            raise CommunicationError(f"Failed to load certificate: {e}")

        # Configure verification
        if self.verify_peer:
            context.verify_mode = ssl.CERT_REQUIRED
            if self.ca_path:
                context.load_verify_locations(cafile=self.ca_path)
                log_event("TLSWrapper", f"Loaded CA certificates from {self.ca_path}")
            else:
                context.load_default_certs()
                log_event("TLSWrapper", "Loaded default CA certificates.")
            log_event("TLSWrapper", "Peer TLS certificate verification enabled.")
        else:
            log_event("TLSWrapper", "Peer TLS certificate verification disabled.")

        # Additional security options
        context.options |= ssl.OP_NO_COMPRESSION  # Disable compression
        context.options |= ssl.OP_SINGLE_DH_USE     # Ensure perfect forward secrecy
        context.options |= ssl.OP_SINGLE_ECDH_USE
        log_event("TLSWrapper", "Enabled additional TLS security options: OP_NO_COMPRESSION, OP_SINGLE_DH_USE, OP_SINGLE_ECDH_USE")

        return context

    def wrap_socket(self, sock: socket.socket, server_side: bool = False, 
                    server_hostname: Optional[str] = None, **kwargs) -> ssl.SSLSocket:
        """Wrap a socket with TLS.
        
        Any extra keyword arguments (e.g. do_handshake_on_connect) are forwarded
        to the underlying SSLContext.wrap_socket() method.
        """
        # Set a default for do_handshake_on_connect if not provided.
        if "do_handshake_on_connect" not in kwargs:
            kwargs["do_handshake_on_connect"] = True

        try:
            log_event("TLSWrapper", f"Wrapping socket with TLS. server_side={server_side}, server_hostname={server_hostname}")
            if server_side:
                ssl_sock = self._ssl_context.wrap_socket(
                    sock,
                    server_side=True,
                    **kwargs
                )
            else:
                ssl_sock = self._ssl_context.wrap_socket(
                    sock,
                    server_side=False,
                    server_hostname=server_hostname,
                    **kwargs
                )
            
            if self.check_ocsp and not server_side:
                self._verify_peer_certificate(ssl_sock)
                
            log_event("TLSWrapper", "Socket wrapped with TLS successfully.")
            return ssl_sock
                
        except ssl.SSLError as e:
            log_error(ErrorCode.TLS_ERROR, f"TLS handshake failed: {e}")
            raise CommunicationError(f"TLS handshake failed: {e}")
        except Exception as e:
            log_error(ErrorCode.GENERAL_ERROR, f"Failed to wrap socket: {e}")
            raise CommunicationError(f"Failed to wrap socket: {e}")

    def _verify_peer_certificate(self, ssl_sock: ssl.SSLSocket):
        """Verify peer's certificate including OCSP check."""
        try:
            log_event("TLSWrapper", "Starting peer certificate verification.")
            cert_bin = ssl_sock.getpeercert(binary_form=True)
            if not cert_bin:
                raise ValueError("No peer certificate")
            
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            log_event("TLSWrapper", f"Peer certificate retrieved with subject: {cert.subject.rfc4514_string()}")
            
            # Get the certificate chain
            chain = self._get_certificate_chain(ssl_sock)
            log_event("TLSWrapper", f"Certificate chain retrieved with {len(chain)} certificates.")
            if not chain:
                raise ValueError("Could not get certificate chain")
                
            # Verify OCSP status
            if self.ocsp_validator and self.check_ocsp:
                issuer_cert = chain[1] if len(chain) > 1 else None
                if not issuer_cert:
                    raise ValueError("Could not find issuer certificate")
                
                log_event("TLSWrapper", f"Performing OCSP check. Certificate subject: {cert.subject.rfc4514_string()}, Issuer subject: {issuer_cert.subject.rfc4514_string()}")
                if not self.ocsp_validator.check_certificate_revocation(cert, issuer_cert):
                    raise ValueError("Certificate has been revoked")
                log_event("TLSWrapper", "OCSP check passed; certificate is not revoked.")
            
            log_event("TLSWrapper", "Peer certificate verified successfully.")
        
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"Peer certificate verification failed: {e}")
            raise CommunicationError(f"Peer certificate verification failed: {e}")

    def _get_certificate_chain(self, ssl_sock: ssl.SSLSocket) -> list:
        """Get the certificate chain from the SSL socket."""
        try:
            log_event("TLSWrapper", "Retrieving peer certificate chain from socket.")
            chain = []
            for index, der_cert in enumerate(ssl_sock.get_peer_cert_chain()):
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                chain.append(cert)
                log_event("TLSWrapper", f"Added certificate {index} to chain: Subject: {cert.subject.rfc4514_string()}")
            if not chain:
                log_error(ErrorCode.SECURITY_ERROR, "Empty certificate chain received.")
            return chain
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"Failed to retrieve certificate chain: {e}")
            return [] 