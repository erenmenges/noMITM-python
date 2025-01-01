import pytest
import json
import socket
import time
import threading
from unittest.mock import Mock, patch
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Communications import (
    SequenceNumberManager, MessageType, packageMessage, 
    validate_message_data, parseMessage, sendData, receiveData,
    MAX_MESSAGE_SIZE
)

@pytest.fixture
def sequence_manager():
    """Fixture to create a fresh SequenceNumberManager for each test."""
    return SequenceNumberManager(test_mode=True)  # Enable test mode

@pytest.fixture
def valid_message_data(sequence_manager):
    """Fixture providing valid message data for tests."""
    return {
        "sequence": sequence_manager.get_next_sequence_number(),
        "encryptedMessage": "encrypted_content",
        "signature": "a" * 128,  # 64-byte hex signature
        "nonce": "a" * 24,      # 12-byte hex nonce (24 characters)
        "timestamp": int(time.time()),
        "type": "data",
        "sender_id": "test_sender"
    }

class TestSequenceNumberManager:
    def test_sequence_number_increment(self, sequence_manager):
        """Test sequence number generation and wraparound."""
        initial = sequence_manager.get_next_sequence_number()
        next_num = sequence_manager.get_next_sequence_number()
        assert next_num == initial + 1
        
        # Test wraparound
        sequence_manager._sequence = 2**32 - 1
        next_num = sequence_manager.get_next_sequence_number()
        assert next_num == 0

    def test_sequence_number_thread_safety(self, sequence_manager):
        """Test thread safety of sequence number generation."""
        sequence_numbers = set()
        num_threads = 100
        
        def get_sequence():
            num = sequence_manager.get_next_sequence_number()
            sequence_numbers.add(num)
        
        threads = [threading.Thread(target=get_sequence) for _ in range(num_threads)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
            
        assert len(sequence_numbers) == num_threads

    def test_sequence_validation(self):
        """Test sequence number validation and replay protection."""
        # Use production mode (test_mode=False) for this test
        sequence_manager = SequenceNumberManager(test_mode=False)
        
        # Test valid sequence
        assert sequence_manager.validate_sequence(1, "sender1") is True
        
        # Test replay attack
        assert sequence_manager.validate_sequence(1, "sender1") is False
        
        # Test sequence window
        assert sequence_manager.validate_sequence(500, "sender1") is True
        assert sequence_manager.validate_sequence(1, "sender1") is False  # Too old
        
        # Test different senders
        assert sequence_manager.validate_sequence(1, "sender2") is True  # Different sender should work
        assert sequence_manager.validate_sequence(1, "sender2") is False  # Replay for sender2

    def test_sequence_test_mode(self):
        """Test sequence number validation in test mode."""
        sequence_manager = SequenceNumberManager(test_mode=True)
        
        # In test mode, replay should be allowed
        assert sequence_manager.validate_sequence(1, "sender1") is True
        assert sequence_manager.validate_sequence(1, "sender1") is True
        
        # Window size checks should still apply
        assert sequence_manager.validate_sequence(500, "sender1") is True
        assert sequence_manager.validate_sequence(1, "sender1") is True  # Should work in test mode

class TestMessageHandling:
    def test_message_packaging(self):
        """Test message packaging functionality."""
        message = packageMessage(
            encryptedMessage="test",
            signature="sig",
            nonce="nonce",
            timestamp=int(time.time()),
            type="data"
        )
        parsed = json.loads(message)
        
        assert "sequence" in parsed
        assert parsed["encryptedMessage"] == "test"
        assert parsed["type"] == "data"

    def test_message_validation(self, valid_message_data):
        """Test message validation with various inputs."""
        # Test valid message
        assert validate_message_data(valid_message_data) is True
        
        # Test missing required field
        invalid_data = valid_message_data.copy()
        del invalid_data["signature"]
        assert validate_message_data(invalid_data) is False
        
        # Test invalid type
        invalid_data = valid_message_data.copy()
        invalid_data["sequence"] = "not_an_integer"
        assert validate_message_data(invalid_data) is False
        
        # Test invalid timestamp
        invalid_data = valid_message_data.copy()
        invalid_data["timestamp"] = int(time.time()) + 301  # Outside allowed window
        assert validate_message_data(invalid_data) is False

    def test_message_parsing(self, valid_message_data, sequence_manager):
        """Test message parsing functionality."""
        # Test valid message
        message = json.dumps(valid_message_data)
        parsed = parseMessage(message, sequence_manager=sequence_manager)
        assert parsed["encryptedMessage"] == "encrypted_content"
        
        # Test oversized message
        with pytest.raises(ValueError):
            oversized_message = json.dumps({
                **valid_message_data,
                "encryptedMessage": "x" * (MAX_MESSAGE_SIZE + 1)
            })
            parseMessage(oversized_message, sequence_manager=sequence_manager)
        
        # Test invalid JSON
        with pytest.raises(ValueError):
            parseMessage("{invalid json", sequence_manager=sequence_manager)

class TestSocketCommunication:
    @pytest.mark.parametrize("test_data,expected_error", [
        ("test data", None),
        ("x" * (MAX_MESSAGE_SIZE + 1), ValueError),
        ("network_error", socket.error),
    ])
    def test_send_data(self, test_data, expected_error):
        """Test sending data over socket with different scenarios."""
        mock_conn = Mock()
        
        if expected_error == socket.error:
            mock_conn.sendall.side_effect = socket.error("Network error")
            
        if expected_error:
            with pytest.raises(expected_error):
                sendData(mock_conn, test_data)
        else:
            sendData(mock_conn, test_data)
            mock_conn.sendall.assert_called_once()

    @pytest.mark.parametrize("mock_data,expected_result,expected_error", [
        ([b"test ", b"data", b""], "test data", None),
        ([socket.timeout()], None, TimeoutError),
        ([b""], None, ConnectionError),
    ])
    def test_receive_data(self, mock_data, expected_result, expected_error):
        """Test receiving data from socket with different scenarios."""
        mock_conn = Mock()
        
        # Handle both exceptions and return values in side_effect
        if isinstance(mock_data[0], Exception):
            mock_conn.recv.side_effect = mock_data[0]
        else:
            mock_conn.recv.side_effect = mock_data
        
        if expected_error:
            with pytest.raises(expected_error):
                receiveData(mock_conn, timeout=0.1)
        else:
            result = receiveData(mock_conn)
            assert result == expected_result

    @pytest.mark.parametrize("msg_type,expected_valid", [
        ("data", True),
        ("keyRenewalRequest", True),
        ("keyRenewalResponse", True),
        ("sessionTermination", True),
        ("acknowledge", True),
        ("error", True),
        ("invalid_type", False),
    ])
    def test_message_types(self, valid_message_data, sequence_manager, msg_type, expected_valid):
        """Test message type validation with different types."""
        # Create test data with a fresh sequence number
        test_data = {
            **valid_message_data,
            "sequence": sequence_manager.get_next_sequence_number(),
            "type": msg_type
        }
        
        # Pass the sequence_manager to validate_message_data
        result = validate_message_data(test_data, sequence_manager=sequence_manager)
        assert result is expected_valid, (
            f"Expected validation to be {expected_valid} for message type '{msg_type}'. "
            f"Valid types are: {[m.value for m in MessageType]}"
        )

@pytest.fixture
def mock_socket():
    """Fixture for mocked socket connection."""
    with patch('socket.socket') as mock:
        yield mock

# Optional: Configure pytest markers
def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )