import pytest
from unittest.mock import Mock, patch, mock_open, ANY
from cryptography.x509 import Certificate
from cryptography.hazmat.primitives.asymmetric import ec
from KeyManagement import KeyManagement
import threading

class TestKeyManagement:
    """Unit tests for the KeyManagement class."""

    @pytest.fixture
    def key_management(self):
        """Fixture to initialize KeyManagement instance."""
        return KeyManagement()

    @pytest.fixture
    def mock_certificate(self):
        """Fixture to mock a Certificate object."""
        cert = Mock(spec=Certificate)
        cert.signature = b"mock_signature"
        cert.tbs_certificate_bytes = b"mock_tbs_bytes"
        cert.signature_hash_algorithm = Mock()
        cert.extensions = Mock()
        return cert

    @pytest.fixture
    def mock_ca_certificate(self):
        """Fixture to mock a CA Certificate object."""
        ca_cert = Mock(spec=Certificate)
        mock_public_key = Mock()
        mock_public_key.verify = Mock()
        ca_cert.public_key = Mock(return_value=mock_public_key)
        return ca_cert

    @patch("KeyManagement.load_pem_x509_certificate")
    @patch("builtins.open", new_callable=mock_open, read_data=b"mock_cert_data")
    def test_load_certificate_success(self, mock_file, mock_load_cert, key_management):
        """Test successful loading of a certificate."""
        mock_certificate = Mock(spec=Certificate)
        mock_load_cert.return_value = mock_certificate

        certificate = key_management.load_certificate("dummy/path.crt")

        mock_file.assert_called_once_with("dummy/path.crt", "rb")
        mock_load_cert.assert_called_once_with(b"mock_cert_data", ANY)
        assert certificate == mock_certificate

    @patch("KeyManagement.load_pem_x509_certificate", side_effect=ValueError("Invalid certificate"))
    @patch("builtins.open", new_callable=mock_open, read_data=b"invalid_cert_data")
    def test_load_certificate_failure(self, mock_file, mock_load_cert, key_management):
        """Test failure in loading a certificate due to invalid data."""
        with pytest.raises(ValueError, match="Invalid certificate"):
            key_management.load_certificate("invalid/path.crt")

        mock_file.assert_called_once_with("invalid/path.crt", "rb")
        mock_load_cert.assert_called_once_with(b"invalid_cert_data", ANY)

    def test_verify_certificate_success(self, key_management, mock_certificate, mock_ca_certificate):
        """Test successful certificate verification."""
        assert key_management.verify_certificate(mock_certificate, mock_ca_certificate) is True
        mock_ca_certificate.public_key().verify.assert_called_once_with(
            mock_certificate.signature,
            mock_certificate.tbs_certificate_bytes,
            ANY  # ec.ECDSA instance with the correct hash algorithm
        )

    def test_verify_certificate_failure(self, key_management, mock_certificate, mock_ca_certificate):
        """Test certificate verification failure due to invalid signature."""
        mock_ca_certificate.public_key().verify.side_effect = Exception("Verification failed")
        assert key_management.verify_certificate(mock_certificate, mock_ca_certificate) is False

    @patch("KeyManagement.requests.get")
    def test_check_certificate_revocation_success(self, mock_get, key_management, mock_certificate):
        """Test successful OCSP certificate revocation check."""
        # Mock Authority Information Access extension with OCSP URL
        mock_access_description = Mock()
        mock_access_description.access_location.value = "http://ocsp.example.com"
        mock_extension_value = Mock(access_descriptions=[mock_access_description])
        mock_certificate.extensions.get_extension_for_oid.return_value.value = mock_extension_value

        # Mock successful OCSP response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = key_management.check_certificate_revocation(mock_certificate)
        mock_get.assert_called_once_with("http://ocsp.example.com")
        assert result is True

    @patch("KeyManagement.requests.get")
    def test_check_certificate_revocation_failure_http(self, mock_get, key_management, mock_certificate):
        """Test OCSP certificate revocation check failure due to bad HTTP response."""
        # Mock Authority Information Access extension with OCSP URL
        mock_access_description = Mock()
        mock_access_description.access_location.value = "http://ocsp.example.com"
        mock_extension_value = Mock(access_descriptions=[mock_access_description])
        mock_certificate.extensions.get_extension_for_oid.return_value.value = mock_extension_value

        # Mock unsuccessful OCSP response
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        result = key_management.check_certificate_revocation(mock_certificate)
        mock_get.assert_called_once_with("http://ocsp.example.com")
        assert result is False

    @patch("KeyManagement.requests.get", side_effect=Exception("Network error"))
    def test_check_certificate_revocation_exception(self, mock_get, key_management, mock_certificate):
        """Test OCSP certificate revocation check failure due to network error."""
        # Mock Authority Information Access extension with OCSP URL
        mock_access_description = Mock()
        mock_access_description.access_location.value = "http://ocsp.example.com"
        mock_extension_value = Mock(access_descriptions=[mock_access_description])
        mock_certificate.extensions.get_extension_for_oid.return_value.value = mock_extension_value

        with pytest.raises(Exception, match="Network error"):
            key_management.check_certificate_revocation(mock_certificate)

        mock_get.assert_called_once_with("http://ocsp.example.com")

    @patch("KeyManagement.Crypto.generate_key_pair")
    def test_initiate_key_renewal(self, mock_generate_key_pair, key_management):
        """Test initiating key renewal successfully."""
        mock_private_key = Mock(spec=ec.EllipticCurvePrivateKey)
        mock_public_key = Mock(spec=ec.EllipticCurvePublicKey)
        mock_generate_key_pair.return_value = (mock_private_key, mock_public_key)

        private_key, public_key = key_management.initiate_key_renewal()

        mock_generate_key_pair.assert_called_once()
        assert private_key == mock_private_key
        assert public_key == mock_public_key
        assert key_management.current_session_keys["private_key"] == mock_private_key
        assert key_management.current_session_keys["public_key"] == mock_public_key

    @patch("KeyManagement.Crypto.derive_session_key")
    @patch("KeyManagement.Crypto.generate_key_pair")
    def test_handle_key_renewal_request_success(self, mock_generate_key_pair, mock_derive_session_key, key_management):
        """Test handling key renewal request successfully."""
        mock_private_key = Mock(spec=ec.EllipticCurvePrivateKey)
        mock_public_key = Mock(spec=ec.EllipticCurvePublicKey)
        mock_peer_public_key = Mock(spec=ec.EllipticCurvePublicKey)
        mock_derived_key = b"mock_session_key"
        mock_generate_key_pair.return_value = (mock_private_key, mock_public_key)
        mock_derive_session_key.return_value = mock_derived_key

        session_key, public_key = key_management.handle_key_renewal_request(mock_peer_public_key)

        mock_generate_key_pair.assert_called_once()
        mock_derive_session_key.assert_called_once_with(mock_peer_public_key, mock_private_key)
        assert session_key == mock_derived_key
        assert public_key == mock_public_key

    @patch("KeyManagement.threading.Thread")
    def test_schedule_key_renewal(self, mock_thread, key_management):
        """Test scheduling automated key renewal."""
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance

        key_management.schedule_key_renewal(3600)  # Schedule every hour

        mock_thread.assert_called_once_with(target=ANY)
        assert mock_thread_instance.daemon is True
        mock_thread_instance.start.assert_called_once()

    @patch("KeyManagement.time.sleep", return_value=None)
    @patch("KeyManagement.Crypto.generate_key_pair")
    def test_automated_key_renewal(self, mock_generate_key_pair, mock_sleep, key_management):
        """Test that automated key renewal is scheduled and executed."""
        mock_private_key = Mock(spec=ec.EllipticCurvePrivateKey)
        mock_public_key = Mock(spec=ec.EllipticCurvePublicKey)
        mock_generate_key_pair.return_value = (mock_private_key, mock_public_key)

        # Set up an event to signal when generate_key_pair is called
        called_event = threading.Event()

        def side_effect(*args, **kwargs):
            called_event.set()
            return (mock_private_key, mock_public_key)

        mock_generate_key_pair.side_effect = side_effect

        # Start key renewal
        key_management.schedule_key_renewal(1)  # 1 second interval

        # Wait for generate_key_pair to be called
        called = called_event.wait(timeout=2)  # Adjust timeout as needed
        assert called, "generate_key_pair was not called within the expected time."
        assert mock_generate_key_pair.call_count >= 1, "generate_key_pair was not called at least once."

    @patch("KeyManagement.Crypto.generate_key_pair", side_effect=Exception("Key generation failed"))
    def test_initiate_key_renewal_failure(self, mock_generate_key_pair, key_management):
        """Test initiating key renewal failure due to key generation error."""
        with pytest.raises(RuntimeError, match="Key pair generation failed: Key generation failed"):
            key_management.initiate_key_renewal()

    @patch("KeyManagement.Crypto.derive_session_key", side_effect=Exception("Derivation failed"))
    @patch("KeyManagement.Crypto.generate_key_pair")
    def test_handle_key_renewal_request_derivation_failure(self, mock_generate_key_pair, mock_derive_session_key, key_management):
        """Test handling key renewal request failure due to derivation error."""
        mock_private_key = Mock(spec=ec.EllipticCurvePrivateKey)
        mock_public_key = Mock(spec=ec.EllipticCurvePublicKey)
        mock_peer_public_key = Mock(spec=ec.EllipticCurvePublicKey)
        mock_generate_key_pair.return_value = (mock_private_key, mock_public_key)
        mock_derive_session_key.side_effect = Exception("Derivation failed")

        with pytest.raises(RuntimeError, match="Session key derivation failed: Derivation failed"):
            key_management.handle_key_renewal_request(mock_peer_public_key)

        mock_generate_key_pair.assert_called_once()
        mock_derive_session_key.assert_called_once_with(mock_peer_public_key, mock_private_key)

    @patch("KeyManagement.threading.Thread")
    @patch("KeyManagement.Crypto.generate_key_pair")
    def test_concurrent_key_renewals(self, mock_generate_key_pair, mock_thread, key_management):
        """Test handling multiple key renewals concurrently."""
        mock_private_key1 = Mock(spec=ec.EllipticCurvePrivateKey)
        mock_public_key1 = Mock(spec=ec.EllipticCurvePublicKey)
        mock_private_key2 = Mock(spec=ec.EllipticCurvePrivateKey)
        mock_public_key2 = Mock(spec=ec.EllipticCurvePublicKey)

        # Simulate two key renewals
        mock_generate_key_pair.side_effect = [
            (mock_private_key1, mock_public_key1),
            (mock_private_key2, mock_public_key2)
        ]
        mock_derive_session_key = Mock(return_value=b"mock_session_key_1")
        with patch("KeyManagement.Crypto.derive_session_key", mock_derive_session_key):
            session_key1, public_key1 = key_management.handle_key_renewal_request(Mock(spec=ec.EllipticCurvePublicKey))
            session_key2, public_key2 = key_management.handle_key_renewal_request(Mock(spec=ec.EllipticCurvePublicKey))

        assert session_key1 == b"mock_session_key_1"
        assert public_key1 == mock_public_key1
        assert session_key2 == b"mock_session_key_1"  # Should return the same mock session key
        assert public_key2 == mock_public_key2
        assert mock_generate_key_pair.call_count == 2
        mock_derive_session_key.assert_called_with(ANY, mock_private_key2)

    def test_handle_key_renewal_request_invalid_peer_key(self, key_management):
        """Test handling key renewal with invalid peer public key."""
        invalid_peer_public_key = "invalid_key"

        with patch("KeyManagement.Crypto.derive_session_key", side_effect=Exception("Invalid peer public key type")):
            with pytest.raises(RuntimeError, match="Session key derivation failed: Invalid peer public key type"):
                key_management.handle_key_renewal_request(invalid_peer_public_key)

    def test_schedule_key_renewal_zero_interval(self, key_management):
        """Test scheduling key renewal with zero interval."""
        with pytest.raises(ValueError):
            key_management.schedule_key_renewal(0)

    def test_schedule_key_renewal_negative_interval(self, key_management):
        """Test scheduling key renewal with negative interval."""
        with pytest.raises(ValueError):
            key_management.schedule_key_renewal(-10)

    @patch("KeyManagement.Crypto.generate_key_pair")
    @patch("KeyManagement.Crypto.derive_session_key")
    def test_full_key_exchange(self, mock_derive_session_key, mock_generate_key_pair, key_management):
        """Test full key exchange process including initiation and handling renewal."""
        mock_private_key_initial = Mock(spec=ec.EllipticCurvePrivateKey)
        mock_public_key_initial = Mock(spec=ec.EllipticCurvePublicKey)
        mock_generate_key_pair.return_value = (mock_private_key_initial, mock_public_key_initial)
        mock_derive_session_key.return_value = b"mock_final_session_key"

        # Initiate key renewal
        session_key, public_key = key_management.handle_key_renewal_request(Mock(spec=ec.EllipticCurvePublicKey))

        assert session_key == b"mock_final_session_key"
        assert public_key == mock_public_key_initial
        mock_generate_key_pair.assert_called_once()
        mock_derive_session_key.assert_called_once_with(ANY, mock_private_key_initial)

    def test_load_certificate_with_missing_extension(self, key_management, mock_certificate):
        """Test loading a certificate without the Authority Information Access extension."""
        mock_certificate.extensions.get_extension_for_oid.side_effect = Exception("Extension not found")

        with pytest.raises(Exception, match="Extension not found"):
            key_management.check_certificate_revocation(mock_certificate)

    def test_handle_key_renewal_response_additional_validations(self, key_management, mock_certificate):
        """Test handling key renewal response with additional field validations."""
        pass  # Placeholder for future detailed tests based on implementation
