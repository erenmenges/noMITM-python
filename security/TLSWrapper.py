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
    def __init__(self, config: TLSConfig):
        self.config = config
        self.ocsp_validator = OCSPValidator() if config.check_ocsp else None
        self._ssl_context = self._create_ssl_context()

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create an SSL context based on configuration."""
        # Set protocol version
        if self.config.min_tls_version == "TLS1_3":
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Set cipher suites
        context.set_ciphers(':'.join(self.config.cipher_suites))

        # Load certificates
        try:
            context.load_cert_chain(
                certfile=self.config.cert_path,
                keyfile=self.config.key_path
            )
            log_event("TLSWrapper", "Loaded server certificate and key successfully.")
        except Exception as e:
            log_error(ErrorCode.CERTIFICATE_ERROR, f"Failed to load certificate: {e}")
            raise CommunicationError(f"Failed to load certificate: {e}")

        # Configure verification
        if self.config.verify_peer:
            context.verify_mode = ssl.CERT_REQUIRED
            if self.config.ca_cert_path:
                context.load_verify_locations(cafile=self.config.ca_cert_path)
            else:
                context.load_default_certs()
            log_event("TLSWrapper", "Configured TLS peer verification.")

        # Additional security options
        context.options |= ssl.OP_NO_COMPRESSION  # Disable compression
        context.options |= ssl.OP_SINGLE_DH_USE  # Ensure perfect forward secrecy
        context.options |= ssl.OP_SINGLE_ECDH_USE

        return context

    def wrap_socket(self, sock: socket.socket, server_side: bool = False, 
                   server_hostname: Optional[str] = None) -> ssl.SSLSocket:
        """Wrap a socket with TLS."""
        try:
            if server_side:
                ssl_sock = self._ssl_context.wrap_socket(
                    sock,
                    server_side=True,
                    do_handshake_on_connect=True
                )
            else:
                ssl_sock = self._ssl_context.wrap_socket(
                    sock,
                    server_side=False,
                    server_hostname=server_hostname,
                    do_handshake_on_connect=True
                )
            
            if self.config.check_ocsp and not server_side:
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
            cert_bin = ssl_sock.getpeercert(binary_form=True)
            if not cert_bin:
                raise ValueError("No peer certificate")
            
            cert = x509.load_der_x509_certificate(cert_bin, default_backend())
            
            # Get the certificate chain
            chain = self._get_certificate_chain(ssl_sock)
            if not chain:
                raise ValueError("Could not get certificate chain")
                
            # Verify OCSP status
            if self.ocsp_validator and self.config.check_ocsp:
                issuer_cert = chain[1] if len(chain) > 1 else None
                if not issuer_cert:
                    raise ValueError("Could not find issuer certificate")
                
                if not self.ocsp_validator.check_certificate_revocation(cert, issuer_cert):
                    raise ValueError("Certificate has been revoked")
            
            log_event("TLSWrapper", "Peer certificate verified successfully.")
        
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"Peer certificate verification failed: {e}")
            raise CommunicationError(f"Peer certificate verification failed: {e}")

    def _get_certificate_chain(self, ssl_sock: ssl.SSLSocket) -> list:
        """Get the certificate chain from the SSL socket."""
        try:
            chain = []
            for der_cert in ssl_sock.get_peer_cert_chain():
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                chain.append(cert)
            if not chain:
                log_error(ErrorCode.SECURITY_ERROR, "Empty certificate chain received.")
            return chain
        except Exception as e:
            log_error(ErrorCode.SECURITY_ERROR, f"Failed to retrieve certificate chain: {e}")
            return [] 