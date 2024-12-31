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

class KeyManagement:
    def __init__(self):
        self._session_keys = {}
        self._key_lock = threading.RLock()  # Use RLock for reentrant locking
        self._renewal_scheduler = None
        
    def get_session_key(self, client_id: str) -> Optional[bytes]:
        """Thread-safe session key retrieval."""
        with self._key_lock:
            return self._session_keys.get(client_id)
            
    def set_session_key(self, client_id: str, key: bytes):
        """Thread-safe session key setting."""
        with self._key_lock:
            self._session_keys[client_id] = key
            
    def remove_session_key(self, client_id: str):
        """Thread-safe session key removal."""
        with self._key_lock:
            self._session_keys.pop(client_id, None)
            
    def clear_session_keys(self):
        """Thread-safe clearing of all session keys."""
        with self._key_lock:
            self._session_keys.clear()
            
    def update_session_keys(self, updates: Dict[str, bytes]):
        """Thread-safe bulk update of session keys."""
        with self._key_lock:
            self._session_keys.update(updates)

    # Certificate Handling with OCSP
    @staticmethod
    def load_certificate(filepath):
        with open(filepath, "rb") as cert_file:
            certificate = load_pem_x509_certificate(cert_file.read(), default_backend())
        return certificate

    @staticmethod
    def verify_certificate(certificate, ca_certificate):
        try:
            ca_public_key = ca_certificate.public_key()
            ca_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(certificate.signature_hash_algorithm)
            )
            return True
        except Exception as e:
            print(f"Certificate verification failed: {e}")
            return False

    @staticmethod
    def check_certificate_revocation(certificate, issuer_certificate):
        logger = logging.getLogger(__name__)

        try:
            aia_extension = certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            )
            ocsp_urls = [
                desc.access_location.value
                for desc in aia_extension.value.access_descriptions
                if desc.access_method == AuthorityInformationAccessOID.OCSP
            ]
            
            if not ocsp_urls:
                raise ValueError("No OCSP URL found in certificate")
            
            ocsp_request_builder = ocsp.OCSPRequestBuilder()
            ocsp_request_builder = ocsp_request_builder.add_certificate(
                certificate,
                issuer_certificate,
                hashes.SHA256()
            )
            ocsp_request = ocsp_request_builder.build()
            ocsp_request_data = ocsp_request.public_bytes(serialization.Encoding.DER)
            headers = {'Content-Type': 'application/ocsp-request'}
            
            for attempt, ocsp_url in enumerate(ocsp_urls):
                try:
                    logger.info(f"Sending OCSP request to {ocsp_url} (attempt {attempt + 1})")
                    response = requests.post(
                        ocsp_url,
                        data=ocsp_request_data,
                        headers=headers,
                        timeout=10
                    )
                    
                    if response.status_code != 200 or response.headers.get('Content-Type') != 'application/ocsp-response':
                        logger.warning(f"Invalid response from {ocsp_url}: status {response.status_code}")
                        continue
                    
                    ocsp_response = ocsp.load_der_ocsp_response(response.content)
                    
                    if ocsp_response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                        logger.warning(f"OCSP response unsuccessful: {ocsp_response.response_status}")
                        continue
                    
                    issuer_public_key = issuer_certificate.public_key()
                    issuer_public_key.verify(
                        ocsp_response.signature,
                        ocsp_response.tbs_response_bytes,
                        ec.ECDSA(ocsp_response.signature_hash_algorithm)
                    )
                    
                    now = datetime.utcnow()
                    if not (ocsp_response.this_update <= now <= ocsp_response.next_update):
                        logger.error("OCSP response is outside its validity period.")
                        continue
                    
                    if ocsp_response.certificate_status == ocsp.OCSPCertStatus.GOOD:
                        logger.info("Certificate status: GOOD")
                        return True
                    elif ocsp_response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
                        logger.warning(f"Certificate status: REVOKED, reason: {ocsp_response.revocation_reason}")
                        return False
                    else:
                        logger.error(f"Unknown certificate status: {ocsp_response.certificate_status}")
                        continue
                
                except Exception as e:
                    logger.error(f"Error during OCSP check for {ocsp_url}: {e}")
                    continue
            
            raise ValueError("All OCSP requests failed or returned invalid responses.")
        
        except Exception as e:
            logger.error(f"Error in OCSP check: {e}")
            raise


    # Session Key Management with Automated Renewal

    def initiate_key_renewal(self):
        try:
            print("Key renewal initiated.")
            private_key, public_key = Crypto.generate_key_pair()
            self.current_session_keys["private_key"] = private_key
            self.current_session_keys["public_key"] = public_key
            return private_key, public_key
        except Exception as e:
            raise RuntimeError(f"Key pair generation failed: {e}") from e

    def handle_key_renewal_request(self, peer_public_key):
        try:
            print("Handling key renewal request.")
            private_key, public_key = Crypto.generate_key_pair()
            session_key = Crypto.derive_session_key(peer_public_key, private_key, b"session key derivation")
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
        """
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
        """
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
                x509.oid.ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value.get_values_for_type(x509.AccessDescription.OCSP)
            
            if not ocsp_servers:
                raise ValueError("No OCSP servers found in certificate")
                
            # Create OCSP request
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(
                certificate, issuer_certificate, hashes.SHA256()
            )
            request = builder.build()
            
            # Check cache first
            cert_id = certificate.fingerprint(hashes.SHA256()).hex()
            cached_response = self._get_cached_response(cert_id)
            if cached_response:
                return self._validate_response(cached_response, certificate, 
                                            issuer_certificate)
            
            # Try each OCSP server
            for server in ocsp_servers:
                try:
                    response = self._get_ocsp_response(server.access_location.value,
                                                     request)
                    if response:
                        self._cache_response(cert_id, response)
                        return self._validate_response(response, certificate,
                                                     issuer_certificate)
                except Exception as e:
                    log_event("OCSP", f"Server check failed: {e}")
                    continue
                    
            raise ValueError("All OCSP servers failed")
            
        except Exception as e:
            log_error(ErrorCode.AUTHENTICATION_ERROR, f"OCSP check failed: {e}")
            raise
            
    def _get_ocsp_response(self, url: str, request: ocsp.OCSPRequest) -> Optional[ocsp.OCSPResponse]:
        """Get OCSP response from server."""
        try:
            response = requests.post(
                url,
                data=request.public_bytes(serialization.Encoding.DER),
                headers={'Content-Type': 'application/ocsp-request'},
                timeout=10
            )
            
            if response.status_code != 200:
                raise ValueError(f"OCSP server returned status {response.status_code}")
                
            return ocsp.load_der_ocsp_response(response.content)
            
        except Exception as e:
            log_event("OCSP", f"Failed to get OCSP response: {e}")
            return None
            
    def _validate_response(self, response: ocsp.OCSPResponse,
                          certificate: x509.Certificate,
                          issuer_certificate: x509.Certificate) -> bool:
        """Validate OCSP response."""
        if response.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
            raise ValueError(f"OCSP response unsuccessful: {response.response_status}")
            
        # Verify response signature
        issuer_public_key = issuer_certificate.public_key()
        try:
            issuer_public_key.verify(
                response.signature,
                response.tbs_response_bytes,
                ec.ECDSA(response.signature_hash_algorithm)
            )
        except InvalidKey:
            raise ValueError("Invalid OCSP response signature")
            
        # Check response validity period
        now = datetime.utcnow()
        if not (response.this_update <= now <= response.next_update):
            raise ValueError("OCSP response is outside its validity period")
            
        # Check certificate status
        if response.certificate_status == ocsp.OCSPCertStatus.GOOD:
            return True
        elif response.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            log_event("Security", f"Certificate revoked: {response.revocation_reason}")
            return False
        else:
            raise ValueError(f"Unknown certificate status: {response.certificate_status}")


