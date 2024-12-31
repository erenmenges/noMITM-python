import unittest
from unittest.mock import patch, MagicMock

import json
import socket
import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))    
import Communications
class TestCommunications(unittest.TestCase):
    """Unit tests for Communications.py functions."""

    def test_packageMessage(self):
        """Test packaging of a message into JSON format."""
        encryptedMessage = "encrypted"
        signature = "signature"
        nonce = "nonce"
        timestamp = 1234567890
        expected = json.dumps({
            "encryptedMessage": encryptedMessage,
            "signature": signature,
            "nonce": nonce,
            "timestamp": timestamp
        })
        result = Communications.packageMessage(encryptedMessage, signature, nonce, timestamp)
        self.assertEqual(result, expected)

    def test_parseMessage_valid(self):
        """Test parsing a valid JSON message."""
        package = json.dumps({
            "key": "value",
            "number": 123
        })
        expected = {
            "key": "value",
            "number": 123
        }
        result = Communications.parseMessage(package)
        self.assertEqual(result, expected)

    def test_parseMessage_invalid_json(self):
        """Test parsing an invalid JSON string."""
        package = "invalid json"
        with self.assertRaises(json.JSONDecodeError):
            Communications.parseMessage(package)

    @patch('socket.socket')
    def test_sendData(self, mock_socket):
        """Test sending data over a socket."""
        destination = ('localhost', 8080)
        data = 'test data'
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance

        Communications.sendData(destination, data)

        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_sock_instance.connect.assert_called_with(destination)
        mock_sock_instance.sendall.assert_called_with(data.encode('utf-8'))

    @patch('socket.socket')
    def test_receiveData(self, mock_socket):
        """Test receiving data over a socket."""
        mock_sock_instance = MagicMock()
        mock_socket.return_value.__enter__.return_value = mock_sock_instance

        # Setup the accept() method to return a connection and address
        mock_conn = MagicMock()
        mock_addr = ('localhost', 12345)
        mock_sock_instance.accept.return_value = (mock_conn, mock_addr)
        mock_conn.recv.return_value = b'test data'

        with patch('builtins.print') as mock_print:
            result = Communications.receiveData()

        mock_socket.assert_called_with(socket.AF_INET, socket.SOCK_STREAM)
        mock_sock_instance.bind.assert_called_with(("0.0.0.0", 8080))
        mock_sock_instance.listen.assert_called()
        mock_sock_instance.accept.assert_called()
        mock_conn.recv.assert_called_with(1024)
        mock_print.assert_called_with(f"Connection established with {mock_addr}")
        self.assertEqual(result, 'test data')

    @patch('Communications.sendData')
    @patch('json.dumps')
    def test_sendKeyRenewalRequest(self, mock_json_dumps, mock_sendData):
        """Test sending a key renewal request."""
        peer = ('localhost', 8080)
        newPublicKey = 'new_public_key'
        timestamp = 1234567890
        with patch('time.time', return_value=timestamp):
            mocked_json = '{"type": "keyRenewalRequest", "newPublicKey": "new_public_key", "timestamp": 1234567890}'
            mock_json_dumps.return_value = mocked_json

            Communications.sendKeyRenewalRequest(peer, newPublicKey)

            mock_json_dumps.assert_called_with({
                "type": "keyRenewalRequest",
                "newPublicKey": newPublicKey,
                "timestamp": timestamp
            })
            mock_sendData.assert_called_with(peer, mocked_json)

    def test_handleKeyRenewalResponse_valid(self):
        """Test handling a valid key renewal response."""
        message = json.dumps({
            "type": "keyRenewalResponse",
            "status": "success",
            "timestamp": 1234567890
        })
        result = Communications.handleKeyRenewalResponse(message)
        expected = {
            "type": "keyRenewalResponse",
            "status": "success",
            "timestamp": 1234567890
        }
        self.assertEqual(result, expected)

    def test_handleKeyRenewalResponse_invalid_type(self):
        """Test handling a response with an invalid message type."""
        message = json.dumps({
            "type": "wrongType",
            "status": "success",
            "timestamp": 1234567890
        })
        with self.assertRaises(ValueError) as context:
            Communications.handleKeyRenewalResponse(message)
        self.assertEqual(str(context.exception), "Invalid message type for key renewal response.")

    def test_handleKeyRenewalResponse_invalid_json(self):
        """Test handling an invalid JSON response."""
        message = "invalid json"
        with self.assertRaises(json.JSONDecodeError):
            Communications.handleKeyRenewalResponse(message)

if __name__ == '__main__':
    unittest.main() 