import unittest
import time
from unittest.mock import patch
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from Utils import NonceManager, ErrorCode, log_event, log_error, log_security_event, throw_error

class TestNonceManager(unittest.TestCase):
    def setUp(self):
        self.nonce_manager = NonceManager()

    def test_generate_nonce_uniqueness(self):
        """Test that generated nonces are unique"""
        nonce1 = self.nonce_manager.generate_nonce()
        nonce2 = self.nonce_manager.generate_nonce()
        self.assertNotEqual(nonce1, nonce2)

    def test_validate_nonce(self):
        """Test nonce validation"""
        nonce = self.nonce_manager.generate_nonce()
        # First validation should succeed
        self.assertTrue(self.nonce_manager.validate_nonce(nonce))
        # Second validation of same nonce should fail
        self.assertFalse(self.nonce_manager.validate_nonce(nonce))

    def test_timestamp_validation(self):
        """Test timestamp validation"""
        current_time = int(time.time())
        
        # Test valid timestamp (within window)
        self.assertTrue(self.nonce_manager.validate_timestamp(current_time))
        
        # Test invalid timestamp (outside window)
        old_timestamp = current_time - 400  # Outside default 300s window
        self.assertFalse(self.nonce_manager.validate_timestamp(old_timestamp))

        # Test custom time window
        self.assertTrue(self.nonce_manager.validate_timestamp(old_timestamp, 500))

class TestLogging(unittest.TestCase):
    @patch('logging.info')
    def test_log_event(self, mock_info):
        """Test event logging"""
        log_event("TEST", "test message")
        mock_info.assert_called_once_with("Event Type: TEST | Message: test message")

    @patch('logging.error')
    def test_log_error(self, mock_error):
        """Test error logging"""
        log_error("E001", "test error")
        mock_error.assert_called_once_with("Error Code: E001 | Error Message: test error")

    @patch('logging.warning')
    def test_log_security_event(self, mock_warning):
        """Test security event logging"""
        log_security_event("BREACH", "test security event")
        mock_warning.assert_called_once_with("Security Event Type: BREACH | Details: test security event")

class TestErrorHandling(unittest.TestCase):
    def test_throw_error_with_enum(self):
        """Test error throwing with ErrorCode enum"""
        with self.assertRaises(Exception) as context:
            throw_error(ErrorCode.INVALID_NONCE)
        
        self.assertIn("INVALID_NONCE", str(context.exception))
        self.assertIn("The provided nonce is invalid", str(context.exception))

    def test_throw_error_with_custom_message(self):
        """Test error throwing with custom message"""
        custom_message = "Custom error message"
        with self.assertRaises(Exception) as context:
            throw_error(ErrorCode.GENERAL_ERROR, custom_message)
        
        self.assertIn("GENERAL_ERROR", str(context.exception))
        self.assertIn(custom_message, str(context.exception))

if __name__ == '__main__':
    unittest.main() 