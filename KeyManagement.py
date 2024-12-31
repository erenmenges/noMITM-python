from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID
from cryptography.x509.extensions import ExtensionNotFound
import requests
import time
import threading
from Crypto import Crypto
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives.asymmetric import padding
import logging
from cryptography.x509 import ocsp, AuthorityInformationAccessOID
import datetime

class KeyManagement:
    def __init__(self):
        self.current_session_keys = {
            "private_key": None,
            "public_key": None
        }

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
                        padding.PKCS1v15(),
                        ocsp_response.signature_hash_algorithm,
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
            session_key = Crypto.derive_session_key(peer_public_key, private_key)
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


