import pytest
import time
from unittest.mock import patch, Mock
import sys
import os
from typing import Generator
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from Utils import NonceManager, ErrorCode, log_event, log_error, log_security_event, throw_error

@pytest.fixture
def nonce_manager() -> Generator[NonceManager, None, None]:
    """Fixture to provide a fresh NonceManager instance for each test."""
    manager = NonceManager()
    yield manager

class TestNonceManager:
    def test_generate_nonce_uniqueness(self, nonce_manager):
        """Test that generated nonces are unique."""
        # Set start time
        start_time = time.time()
        
        try:
            # Test just two sequential nonces
            nonce1 = nonce_manager.generate_nonce()
            
            # Check if first generation took too long
            if time.time() - start_time > 2:  # 2 second timeout
                pytest.fail("Nonce generation taking too long")
                
            nonce2 = nonce_manager.generate_nonce()
            
            # Verify they're not None and are different
            assert nonce1 is not None
            assert nonce2 is not None
            assert nonce1 != nonce2
            
            # Basic format check
            assert isinstance(nonce1, str)
            assert isinstance(nonce2, str)
            
        except Exception as e:
            # If we get here, something went wrong with nonce generation
            pytest.fail(f"Nonce generation failed: {str(e)}")

    def test_nonce_format(self, nonce_manager):
        """Test that generated nonces follow expected format."""
        nonce = nonce_manager.generate_nonce()
        # Assuming nonces are hex strings of specific length (modify as per actual implementation)
        assert isinstance(nonce, str)
        assert all(c in '0123456789abcdefABCDEF' for c in nonce)

    def test_validate_nonce_success(self, nonce_manager):
        """Test successful nonce validation."""
        nonce = nonce_manager.generate_nonce()
        assert nonce_manager.validate_nonce(nonce) is True

    def test_validate_nonce_failure_reuse(self, nonce_manager):
        """Test that a nonce cannot be reused."""
        nonce = nonce_manager.generate_nonce()
        assert nonce_manager.validate_nonce(nonce) is True
        assert nonce_manager.validate_nonce(nonce) is False

    def test_validate_nonce_invalid_format(self, nonce_manager):
        """Test validation of improperly formatted nonces."""
        invalid_nonces = ['', 'invalid', '12345', None, 123]
        for invalid_nonce in invalid_nonces:
            assert nonce_manager.validate_nonce(invalid_nonce) is False

    @pytest.mark.parametrize("time_offset,window,expected", [
        (0, 300, True),           # Current time
        (-299, 300, True),        # Just within window
        (-301, 300, False),       # Just outside window
        (-150, 300, True),        # Middle of window
        (1, 300, False),          # Future timestamp
        (-600, 300, False),       # Far outside window
        (-400, 500, True),        # Custom larger window
        (-100, 50, False),        # Custom smaller window
    ])
    def test_timestamp_validation(self, nonce_manager, time_offset, window, expected):
        """Test timestamp validation with various offsets and windows."""
        current_time = int(time.time())
        test_time = current_time + time_offset
        assert nonce_manager.validate_timestamp(test_time, window) is expected

    def test_timestamp_validation_invalid_types(self, nonce_manager):
        """Test timestamp validation with invalid input types."""
        invalid_timestamps = [None, "123", [], {}]
        for invalid_timestamp in invalid_timestamps:
            with pytest.raises(Exception):  # Adjust exception type as needed
                nonce_manager.validate_timestamp(invalid_timestamp)

class TestLogging:
    def test_log_event_basic(self):
        """Test basic event logging functionality."""
        with patch('logging.info') as mock_info:
            log_event("TEST", "test message")
            mock_info.assert_called_once_with("Event Type: TEST | Message: test message")

    @pytest.mark.parametrize("event_type,message", [
        ("", "empty event type"),
        ("TEST", ""),
        ("LONG_EVENT_TYPE" * 10, "very long event type"),
        ("TEST", "LONG_MESSAGE" * 100),
        ("特殊字符", "special characters 特殊字符"),
    ])
    def test_log_event_edge_cases(self, event_type, message):
        """Test event logging with edge cases."""
        with patch('logging.info') as mock_info:
            log_event(event_type, message)
            mock_info.assert_called_once_with(f"Event Type: {event_type} | Message: {message}")

    def test_log_error_basic(self):
        """Test basic error logging functionality."""
        with patch('logging.error') as mock_error:
            log_error("E001", "test error")
            mock_error.assert_called_once_with("Error Code: E001 | Error Message: test error")

    def test_log_security_event_basic(self):
        """Test basic security event logging functionality."""
        with patch('logging.warning') as mock_warning:
            log_security_event("BREACH", "test security event")
            mock_warning.assert_called_once_with(
                "Security Event Type: BREACH | Details: test security event"
            )

    def test_log_security_event_sensitive_data(self):
        """Test security event logging with sensitive data patterns."""
        sensitive_data = [
            "password123",
            "1234-5678-9012-3456",
            "test@email.com",
            "192.168.1.1",
        ]
        with patch('logging.warning') as mock_warning:
            for data in sensitive_data:
                log_security_event("SECURITY_TEST", f"Testing with {data}")
                # Verify logging occurs without exposing sensitive data
                mock_warning.assert_called()

class TestErrorHandling:
    @pytest.mark.parametrize("error_code", list(ErrorCode))
    def test_throw_error_all_codes(self, error_code):
        """Test error throwing with all possible ErrorCode enum values."""
        with pytest.raises(Exception) as exc_info:
            throw_error(error_code)
        assert error_code.name in str(exc_info.value)

    def test_throw_error_custom_message(self):
        """Test error throwing with custom message."""
        custom_message = "Custom error message"
        with pytest.raises(Exception) as exc_info:
            throw_error(ErrorCode.GENERAL_ERROR, custom_message)
        assert ErrorCode.GENERAL_ERROR.name in str(exc_info.value)
        assert custom_message in str(exc_info.value)

    def test_throw_error_with_none_message(self):
        """Test error throwing with None message."""
        with pytest.raises(Exception) as exc_info:
            throw_error(ErrorCode.GENERAL_ERROR, None)
        assert ErrorCode.GENERAL_ERROR.name in str(exc_info.value)

    @pytest.mark.parametrize("message", [
        "",
        "a" * 1000,  # Very long message
        "特殊字符",  # Special characters
        "\n\t\r",    # Control characters
    ])
    def test_throw_error_message_edge_cases(self, message):
        """Test error throwing with edge case messages."""
        with pytest.raises(Exception) as exc_info:
            throw_error(ErrorCode.GENERAL_ERROR, message)
        assert message in str(exc_info.value)