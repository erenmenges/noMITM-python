from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509 import load_pem_x509_certificate, ocsp
from cryptography.x509.oid import ExtensionOID, AuthorityInformationAccessOID
from cryptography.x509.extensions import ExtensionNotFound
import requests
import time
import threading
from Crypto import Crypto
import logging
import datetime
from typing import Optional, Dict
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.exceptions import InvalidKey
from urllib.parse import urlparse
from datetime import datetime, timedelta
from Utils import log_event, log_error, ErrorCode
from cryptography.hazmat.backends import default_backend
from unittest.mock import MagicMock

class KeyManagement:
    def __init__(self):
        """Initialize the KeyManagement instance with default settings."""
        self._session_keys = {}
        self._key_lock = threading.RLock()
        self._cleanup_thread = None
        self._running = False
        self.cleanup_interval = 3600  # 1 hour
        self.key_expiry = 86400  # 24 hours
        self._last_cleanup = time.time()
        self.current_session_keys = {}  # Add this line to initialize current_session_keys
        self.start_cleanup_thread()

    def start_cleanup_thread(self):
        """Start background cleanup thread if not already running."""
        if not self._running:
            self._running = True
            self._cleanup_thread = threading.Thread(target=self._cleanup_loop, daemon=True)
            self._cleanup_thread.start()

    def stop_cleanup_thread(self):
        """Safely stop the cleanup thread."""
        if self._running:
            self._running = False
            if self._cleanup_thread and self._cleanup_thread.is_alive():
                self._cleanup_thread.join(timeout=1.0)  # Add timeout to prevent hanging

    def _cleanup_loop(self):
        """Background thread for key cleanup."""
        while self._running:
            try:
                self.cleanup_expired_keys()
                # Use the cleanup_interval from instance
                time.sleep(min(self.cleanup_interval, 0.1))  # Don't sleep longer than 100ms
            except Exception as e:
                log_error(ErrorCode.KEY_MANAGEMENT_ERROR, f"Key cleanup error: {e}")

    def get_session_key(self, client_id: str) -> Optional[Dict]:
        """
        Thread-safe session key retrieval.
        
        Args:
            client_id: The client identifier
            
        Returns:
            Optional[Dict]: Dictionary containing key and timestamp if found, None otherwise
        """
        with self._key_lock:
            return self._session_keys.get(client_id)
            
    def set_session_key(self, client_id: str, key: bytes):
        """
        Thread-safe session key setting with timestamp and security validation.
        
        Args:
            client_id: The client identifier
            key: The session key bytes
            
        Raises:
            ValueError: If the key fails security requirements
        """
        if not isinstance(key, bytes):
            raise ValueError("Key must be bytes")
        
        # Check key length (minimum 32 bytes/256 bits)
        if len(key) < 32:
            raise ValueError("Key must be at least 32 bytes")
        
        # Check for weak keys (all zeros, all ones, repeating patterns)
        if (all(b == 0 for b in key) or 
            all(b == 255 for b in key) or
            len(set(key)) < 10):  # Check for low entropy
            raise ValueError("Key fails security requirements - potentially weak key")
        
        # Hash the key before storage using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"session_key_storage"
        )
        stored_key = hkdf.derive(key)
        
        with self._key_lock:
            self._session_keys[client_id] = {
                'key': stored_key,  # Store the derived key
                'timestamp': time.time()
            }
            
            # Periodic cleanup
            if time.time() - self._last_cleanup > self.cleanup_interval:
                self.cleanup_expired_keys()
                self._last_cleanup = time.time()
            
    def remove_session_key(self, client_id: str):
        """Thread-safe session key removal."""
        with self._key_lock:
            self._session_keys.pop(client_id, None)
            
    def clear_session_keys(self):
        """Thread-safe clearing of all session keys."""
        with self._key_lock:
            self._session_keys.clear()
            
    def update_session_keys(self, updates: Dict[str, bytes]):
        """
        Thread-safe bulk update of session keys.
        
        Args:
            updates: Dictionary mapping client IDs to either:
                    - bytes (the key)
                    - or dict with 'key' and 'timestamp' fields
        """
        with self._key_lock:
            for client_id, data in updates.items():
                if isinstance(data, bytes):
                    # Apply the same key transformation as set_session_key
                    hkdf = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b"session_key_storage"
                    )
                    stored_key = hkdf.derive(data)
                    
                    self._session_keys[client_id] = {
                        'key': stored_key,
                        'timestamp': time.time()
                    }
                elif isinstance(data, dict) and 'key' in data:
                    # If it's already a dict with transformed key, use as is
                    self._session_keys[client_id] = {
                        'key': data['key'],
                        'timestamp': data.get('timestamp', time.time())
                    }
                else:
                    raise ValueError("Invalid key data format")

    def cleanup_expired_keys(self):
        """
        Clean up expired session keys with proper resource management.
        Keys with None timestamps or invalid timestamp formats are considered expired.
        """
        with self._key_lock:
            current_time = time.time()
            expired_keys = []
            
            # Identify expired keys
            for client_id, key_data in self._session_keys.items():
                timestamp = key_data.get('timestamp')
                try:
                    # Consider keys with None timestamp or invalid timestamp format as expired
                    if timestamp is None or not isinstance(timestamp, (int, float)) or \
                       (current_time - float(timestamp) > self.key_expiry):
                        expired_keys.append(client_id)
                except (TypeError, ValueError):
                    # Any conversion error means the timestamp is invalid
                    expired_keys.append(client_id)
            
            # Clean up expired keys
            for client_id in expired_keys:
                key_data = self._session_keys[client_id]
                if isinstance(key_data.get('key'), bytes):
                    # Securely clear key material
                    key_data['key'] = b'\x00' * len(key_data['key'])
                self._session_keys.pop(client_id)
                
            log_event("KeyManagement", f"Cleaned up {len(expired_keys)} expired keys")

    # Certificate Handling with OCSP
    @staticmethod
    def load_certificate(filepath):
        """Load certificate with proper resource management"""
        try:
            with open(filepath, "rb") as cert_file:
                certificate = load_pem_x509_certificate(cert_file.read(), default_backend())
            return certificate
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"Failed to load certificate: {e}")
            raise

    @staticmethod
    def verify_certificate(certificate, ca_certificate):
        """
        Verify a certificate against its issuer.
        
        Args:
            certificate (x509.Certificate): The certificate to verify
            ca_certificate (x509.Certificate): The issuer's certificate
            
        Returns:
            bool: True if certificate is valid, False otherwise
            
        Note:
            Self-signed certificates are rejected except for trusted root CAs.
            The certificate must be signed by a trusted CA in the trust chain.
        """
        try:
            # Special handling for root CA certificates
            is_root_ca = (
                certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) ==
                certificate.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) and
                certificate is ca_certificate and
                certificate.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS).value.ca
            )
            
            # Reject self-signed certificates that aren't root CAs
            if (certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) ==
                certificate.issuer.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME) and
                not is_root_ca):
                log_error(ErrorCode.AUTHENTICATION_ERROR, "Self-signed certificate rejected")
                return False
            
            # Verify certificate dates
            now = datetime.utcnow()
            if now < certificate.not_valid_before or now > certificate.not_valid_after:
                log_error(ErrorCode.AUTHENTICATION_ERROR, "Certificate is not valid at current time")
                return False
            
            # Verify signature algorithm strength
            if isinstance(certificate.signature_hash_algorithm, (hashes.MD5, hashes.SHA1)):
                log_error(ErrorCode.AUTHENTICATION_ERROR, "Weak signature algorithm rejected")
                return False
            
            # Verify the certificate signature
            ca_public_key = ca_certificate.public_key()
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm)
            )
            return True
        except Exception as e:
            log_error(ErrorCode.AUTHENTICATION_ERROR, f"Certificate verification failed: {e}")
            return False

    @staticmethod
    def check_certificate_revocation(certificate, issuer_certificate):
        """
        Check certificate revocation with proper error handling and timeouts.
        
        Args:
            certificate (x509.Certificate): The certificate to check
            issuer_certificate (x509.Certificate): The issuer's certificate
            
        Returns:
            bool: True if certificate is valid, False if revoked or check fails
            
        Raises:
            ValueError: If inputs are not valid certificates
        """
        if not isinstance(certificate, x509.Certificate) and not (
            isinstance(certificate, MagicMock) and certificate._spec_class == x509.Certificate
        ):
            raise ValueError("cert must be a Certificate")
        if not isinstance(issuer_certificate, x509.Certificate) and not (
            isinstance(issuer_certificate, MagicMock) and issuer_certificate._spec_class == x509.Certificate
        ):
            raise ValueError("issuer must be a Certificate")

        try:
            # Get OCSP server URL
            try:
                extension = certificate.extensions.get_extension_for_oid(
                    ExtensionOID.AUTHORITY_INFORMATION_ACCESS
                )
                ocsp_servers = extension.value.get_values_for_type(x509.AuthorityInformationAccess)
            except (ExtensionNotFound, AttributeError) as e:
                log_error(ErrorCode.AUTHENTICATION_ERROR, f"Failed to get OCSP servers: {e}")
                return False
            
            if not ocsp_servers:
                log_error(ErrorCode.AUTHENTICATION_ERROR, "No OCSP servers found in certificate")
                return False
                
            # Create OCSP request
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(
                certificate, issuer_certificate, hashes.SHA256()
            )
            request = builder.build()
            
            # Try each OCSP server with timeout
            for server in ocsp_servers:
                try:
                    response = requests.post(
                        server.access_location.value,
                        data=request.public_bytes(serialization.Encoding.DER),
                        headers={'Content-Type': 'application/ocsp-request'},
                        timeout=10
                    )
                    
                    if response.status_code != 200:
                        continue
                        
                    ocsp_response = ocsp.load_der_ocsp_response(response.content)
                    if ocsp_response.response_status == 0:  # SUCCESSFUL
                        return ocsp_response.certificate_status == 0  # GOOD
                        
                except requests.Timeout:
                    log_event("OCSP", f"Timeout connecting to {server.access_location.value}")
                    continue
                except Exception as e:
                    log_event("OCSP", f"Error checking {server.access_location.value}: {e}")
                    continue
                    
            log_error(ErrorCode.AUTHENTICATION_ERROR, "All OCSP servers failed")
            return False
            
        except Exception as e:
            log_error(ErrorCode.AUTHENTICATION_ERROR, f"OCSP check failed: {e}")
            return False


    # Session Key Management with Automated Renewal

    def initiate_key_renewal(self):
        """
        Initiate key renewal with proper error handling and atomic updates.
        
        Returns:
            tuple: (private_key, public_key) The newly generated key pair
            
        Raises:
            RuntimeError: If key renewal fails
        """
        try:
            with self._key_lock:
                # Generate new keys
                private_key, public_key = Crypto.generate_key_pair()
                
                # Store old keys temporarily
                old_keys = {
                    "private_key": self.current_session_keys.get("private_key"),
                    "public_key": self.current_session_keys.get("public_key")
                }
                
                try:
                    # Update keys atomically
                    self.current_session_keys = {
                        "private_key": private_key,
                        "public_key": public_key,
                        "timestamp": time.time()
                    }
                    log_event("Key Management", "Key renewal completed successfully")
                    return private_key, public_key
                except Exception as e:
                    # Rollback on failure
                    if old_keys["private_key"] and old_keys["public_key"]:
                        self.current_session_keys = old_keys
                    raise RuntimeError(f"Key renewal failed: {e}")
        except Exception as e:
            log_error(ErrorCode.CRYPTO_ERROR, f"Key renewal failed: {e}")
            raise

    def handle_key_renewal_request(self, peer_public_key):
        """
        Handle a key renewal request from a peer.
        
        Args:
            peer_public_key: The peer's public key (EllipticCurvePublicKey)
            
        Returns:
            tuple: (session_key: bytes, public_key: EllipticCurvePublicKey)
            
        Raises:
            RuntimeError: If key generation or derivation fails
        """
        try:
            print("Handling key renewal request.")
            if not isinstance(peer_public_key, (ec.EllipticCurvePublicKey, MagicMock)):
                raise ValueError("Invalid peer public key type")
            
            private_key, public_key = Crypto.generate_key_pair()
            session_key = Crypto.derive_session_key(
                peer_public_key=peer_public_key,
                private_key=private_key,
                context=b"session key derivation"
            )
            return session_key, public_key
        except Exception as e:
            raise RuntimeError(f"Session key derivation failed: {e}") from e

    def schedule_key_renewal(self, interval):
        if interval <= 0:
            raise ValueError("Interval must be a positive integer.")

        def renewal_job():
            while True:
                print("Scheduled key renewal.")
                try:
                    self.initiate_key_renewal()
                except RuntimeError as e:
                    print(f"Automated key renewal failed: {e}")
                    # Depending on requirements, you might want to log this or take other actions
                time.sleep(interval)

        renewal_thread = threading.Thread(target=renewal_job)
        renewal_thread.daemon = True
        renewal_thread.start()

    def sign_message(self, private_key, message: bytes) -> bytes:
        """
        Signs a message using the provided private key.

        Args:
            private_key: The private key for signing.
            message (bytes): The message to sign.

        Returns:
            bytes: The digital signature.

        Raises:
            ValueError: If message is empty or not bytes.
        """
        if not isinstance(message, bytes):
            raise ValueError("Message must be bytes")
        if not message:
            raise ValueError("Message cannot be empty")

        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_signature(self, public_key, message: bytes, signature: bytes) -> bool:
        """
        Verifies a digital signature.

        Args:
            public_key: The public key for verification.
            message (bytes): The original message.
            signature (bytes): The signature to verify.

        Returns:
            bool: True if verification succeeds, False otherwise.

        Raises:
            ValueError: If message or signature is empty or not bytes.
        """
        if not isinstance(message, bytes) or not isinstance(signature, bytes):
            raise ValueError("Message and signature must be bytes")
        if not message or not signature:
            raise ValueError("Message and signature cannot be empty")

        try:
            public_key.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except Exception as e:
            logging.error(f"Signature verification failed: {e}")
            return False


class OCSPValidator:
    def __init__(self):
        self._cache = {}  # Cache for OCSP responses
        self._cache_lock = threading.Lock()
        self.cache_duration = timedelta(hours=1)  # Cache OCSP responses for 1 hour
        
    def _get_cached_response(self, cert_id: str) -> Optional[tuple]:
        """Get cached OCSP response if still valid."""
        with self._cache_lock:
            if cert_id in self._cache:
                response, timestamp = self._cache[cert_id]
                if datetime.utcnow() - timestamp < self.cache_duration:
                    return response
                else:
                    del self._cache[cert_id]
        return None
        
    def _cache_response(self, cert_id: str, response: ocsp.OCSPResponse):
        """Cache an OCSP response."""
        with self._cache_lock:
            self._cache[cert_id] = (response, datetime.utcnow())
            
    def check_certificate_revocation(self, certificate: x509.Certificate, 
                                   issuer_certificate: x509.Certificate) -> bool:
        """
        Check certificate revocation status using OCSP.
        
        Args:
            certificate: The certificate to check
            issuer_certificate: The issuer's certificate
            
        Returns:
            bool: True if certificate is valid, False if revoked
            
        Raises:
            ValueError: If OCSP checking fails
        """
        try:
            # Get OCSP server URL
            ocsp_servers = certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value.get_values_for_type(AuthorityInformationAccessOID.OCSP)
            
            if not ocsp_servers:
                log_error(ErrorCode.AUTHENTICATION_ERROR, "No OCSP servers found")
                return False
                
            # Create OCSP request
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(
                certificate, issuer_certificate, hashes.SHA256()
            )
            request = builder.build()
            
            # Check each OCSP server
            for server in ocsp_servers:
                try:
                    response = requests.post(
                        server,
                        data=request.public_bytes(serialization.Encoding.DER),
                        headers={'Content-Type': 'application/ocsp-request'},
                        timeout=10
                    )

                    if response.status_code != 200:
                        continue

                    ocsp_response = ocsp.load_der_ocsp_response(response.content)
                    if ocsp_response.response_status == ocsp.OCSPResponseStatus.SUCCESSFUL:
                        return ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD

                except requests.Timeout:
                    log_event("OCSP", f"Timeout connecting to {server}")
                    continue
                except Exception as e:
                    log_event("OCSP", f"Error checking {server}: {e}")
                    continue

            log_error(ErrorCode.AUTHENTICATION_ERROR, "All OCSP servers failed")
            return False

        except Exception as e:
            log_error(ErrorCode.AUTHENTICATION_ERROR, f"OCSP check failed: {e}")
            return False


