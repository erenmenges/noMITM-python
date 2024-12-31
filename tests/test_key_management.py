import pytest
from unittest.mock import Mock, patch, mock_open, ANY
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import Certificate
from cryptography.x509.oid import ExtensionOID
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from KeyManagement import KeyManagement

@pytest.fixture
def key_management():
    return KeyManagement()

@pytest.fixture
def mock_certificate():
    cert = Mock(spec=Certificate)
    cert.signature = b"mock_signature"
    cert.tbs_certificate_bytes = b"mock_tbs_bytes"
    cert.signature_hash_algorithm = Mock()
    return cert

@pytest.fixture
def mock_ca_certificate():
    ca_cert = Mock(spec=Certificate)
    mock_public_key = Mock()
    mock_public_key.verify = Mock()
    ca_cert.public_key = Mock(return_value=mock_public_key)
    return ca_cert

class TestKeyManagement:
    def test_init(self, key_management):
        assert key_management.current_session_keys["private_key"] is None
        assert key_management.current_session_keys["public_key"] is None

    @patch("builtins.open", new_callable=mock_open, read_data=b"mock_cert_data")
    @patch("KeyManagement.load_pem_x509_certificate")
    def test_load_certificate(self, mock_load_cert, mock_file, key_management):
        mock_certificate = Mock()
        mock_load_cert.return_value = mock_certificate
        
        result = KeyManagement.load_certificate("dummy/path")
        
        mock_file.assert_called_once_with("dummy/path", "rb")
        mock_load_cert.assert_called_once()
        assert result == mock_certificate

    @patch("cryptography.hazmat.primitives.asymmetric.ec.ECDSA")
    def test_verify_certificate_success(self, mock_ecdsa, key_management, mock_certificate, mock_ca_certificate):
        # Set up the signature hash algorithm correctly
        mock_certificate.signature_hash_algorithm = hashes.SHA256()  # Use hashes.SHA256
        
        # Execute the method
        result = KeyManagement.verify_certificate(mock_certificate, mock_ca_certificate)
        
        # Assert ECDSA was instantiated with the correct hash algorithm
        mock_ecdsa.assert_called_once_with(mock_certificate.signature_hash_algorithm)
        
        # Assert verify was called with the correct parameters
        mock_ca_certificate.public_key().verify.assert_called_once_with(
            mock_certificate.signature,
            mock_certificate.tbs_certificate_bytes,
            mock_ecdsa.return_value  # Use the mocked ECDSA instance
        )
        
        assert result is True

    def test_verify_certificate_failure(self, key_management, mock_certificate, mock_ca_certificate):
        mock_ca_certificate.public_key().verify.side_effect = Exception("Verification failed")
        
        result = KeyManagement.verify_certificate(mock_certificate, mock_ca_certificate)
        
        assert result is False

    @patch("requests.get")
    def test_check_certificate_revocation_success(self, mock_get, key_management, mock_certificate):
        # Use the correct OID for Authority Information Access
        mock_access_description = Mock()
        mock_access_description.access_location.value = "http://ocsp.example.com"
        mock_extension_value = Mock(access_descriptions=[mock_access_description])
        mock_certificate.extensions.get_extension_for_oid.return_value = Mock(value=mock_extension_value)
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = KeyManagement.check_certificate_revocation(mock_certificate)
        
        assert result is True
        mock_get.assert_called_once_with("http://ocsp.example.com")

    @patch("KeyManagement.Crypto")
    def test_initiate_key_renewal(self, mock_crypto, key_management):
        mock_private_key = Mock()
        mock_public_key = Mock()
        mock_crypto.generate_key_pair.return_value = (mock_private_key, mock_public_key)

        private_key, public_key = key_management.initiate_key_renewal()

        assert private_key == mock_private_key
        assert public_key == mock_public_key
        assert key_management.current_session_keys["private_key"] == mock_private_key
        assert key_management.current_session_keys["public_key"] == mock_public_key

    @patch("KeyManagement.Crypto")
    def test_handle_key_renewal_request(self, mock_crypto, key_management):
        mock_private_key = Mock()
        mock_public_key = Mock()
        mock_session_key = Mock()
        mock_peer_public_key = Mock()
        
        mock_crypto.generate_key_pair.return_value = (mock_private_key, mock_public_key)
        mock_crypto.derive_session_key.return_value = mock_session_key

        session_key, public_key = key_management.handle_key_renewal_request(mock_peer_public_key)

        mock_crypto.generate_key_pair.assert_called_once()
        mock_crypto.derive_session_key.assert_called_once_with(mock_peer_public_key, mock_private_key)
        assert session_key == mock_session_key
        assert public_key == mock_public_key

    @patch("threading.Thread")
    def test_schedule_key_renewal(self, mock_thread, key_management):
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        
        key_management.schedule_key_renewal(3600)
        
        mock_thread.assert_called_once()
        assert mock_thread_instance.daemon is True
        mock_thread_instance.start.assert_called_once() 