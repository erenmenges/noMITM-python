import unittest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey
import os
import secrets
import logging
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from typing import Tuple

from Crypto import Crypto, CryptoConstants, SecureMessage

class TestCrypto(unittest.TestCase):
    def setUp(self):
        """Initialize the Crypto instance and test data"""
        self.crypto = Crypto()
        self.test_data = b"Hello, World!"
        self.test_key = secrets.token_bytes(CryptoConstants.AES_KEY_SIZE)
        self.test_context = b"test_context"

    def generate_key_pair_for_test(self) -> Tuple[ec.EllipticCurvePublicKey, ec.EllipticCurvePrivateKey]:
        """Helper method to generate a key pair for testing"""
        private_key = ec.generate_private_key(
            CryptoConstants.CURVE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return public_key, private_key

    def test_init(self):
        """Test initialization and random number generator availability"""
        self.assertIsInstance(self.crypto, Crypto)
        # Test that os.urandom is available
        self.assertTrue(os.urandom(1))

    def test_generate_key_pair(self):
        """Test key pair generation"""
        public_pem, private_pem = self.crypto.generate_key_pair()
        
        # Test that keys are bytes
        self.assertIsInstance(public_pem, bytes)
        self.assertIsInstance(private_pem, bytes)
        
        # Test that keys can be loaded
        public_key = serialization.load_pem_public_key(public_pem)
        self.assertIsInstance(public_key, ec.EllipticCurvePublicKey)

    def test_derive_session_key(self):
        """Test session key derivation"""
        # Generate two pairs of keys
        public_key1, private_key1 = self.generate_key_pair_for_test()
        public_key2, private_key2 = self.generate_key_pair_for_test()

        # Derive session keys from both sides
        key1 = self.crypto.derive_session_key(public_key2, private_key1, self.test_context)
        key2 = self.crypto.derive_session_key(public_key1, private_key2, self.test_context)

        # Keys should be the same
        self.assertEqual(key1, key2)
        self.assertEqual(len(key1), CryptoConstants.AES_KEY_SIZE)

    def test_encrypt_decrypt(self):
        """Test encryption and decryption"""
        # Encrypt data
        secure_msg = self.crypto.encrypt(self.test_data, self.test_key)
        
        # Test SecureMessage structure
        self.assertIsInstance(secure_msg, SecureMessage)
        self.assertEqual(secure_msg.version, CryptoConstants.VERSION)
        self.assertEqual(len(secure_msg.nonce), CryptoConstants.NONCE_SIZE)
        self.assertEqual(len(secure_msg.salt), CryptoConstants.SALT_SIZE)
        
        # Decrypt data
        decrypted = self.crypto.decrypt(secure_msg, self.test_key)
        self.assertEqual(decrypted, self.test_data)

    def test_encrypt_decrypt_wrong_key(self):
        """Test decryption with wrong key"""
        secure_msg = self.crypto.encrypt(self.test_data, self.test_key)
        wrong_key = secrets.token_bytes(CryptoConstants.AES_KEY_SIZE)
        
        with self.assertRaises(RuntimeError):
            self.crypto.decrypt(secure_msg, wrong_key)

    def test_hash(self):
        """Test hashing functionality"""
        hash1 = self.crypto.hash(self.test_data)
        hash2 = self.crypto.hash(self.test_data)
        
        # Same data should produce same hash
        self.assertEqual(hash1, hash2)
        
        # Different data should produce different hash
        hash3 = self.crypto.hash(b"Different data")
        self.assertNotEqual(hash1, hash3)

    def test_mac(self):
        """Test MAC creation and verification"""
        mac = self.crypto.create_mac(self.test_key, self.test_data)
        
        # Verify MAC
        self.assertTrue(self.crypto.verify_mac(self.test_key, self.test_data, mac))
        
        # Test wrong data
        self.assertFalse(self.crypto.verify_mac(self.test_key, b"Wrong data", mac))
        
        # Test wrong key
        wrong_key = secrets.token_bytes(CryptoConstants.AES_KEY_SIZE)
        self.assertFalse(self.crypto.verify_mac(wrong_key, self.test_data, mac))

    def test_secure_message_serialization(self):
        """Test SecureMessage serialization and deserialization"""
        secure_msg = self.crypto.encrypt(self.test_data, self.test_key)
        
        # Convert to dict and back
        msg_dict = secure_msg.to_dict()
        restored_msg = SecureMessage.from_dict(msg_dict)
        
        # Check all fields match
        self.assertEqual(secure_msg.ciphertext, restored_msg.ciphertext)
        self.assertEqual(secure_msg.nonce, restored_msg.nonce)
        self.assertEqual(secure_msg.tag, restored_msg.tag)
        self.assertEqual(secure_msg.version, restored_msg.version)
        self.assertEqual(secure_msg.salt, restored_msg.salt)

    def test_invalid_key_size(self):
        """Test handling of invalid key sizes"""
        invalid_key = secrets.token_bytes(16)  # Wrong size
        with self.assertRaises(ValueError):
            self.crypto.encrypt(self.test_data, invalid_key)

    def test_invalid_version(self):
        """Test handling of invalid version"""
        secure_msg = self.crypto.encrypt(self.test_data, self.test_key)
        secure_msg.version = 999  # Invalid version
        
        with self.assertRaises(ValueError):
            self.crypto.decrypt(secure_msg, self.test_key)

    def test_large_data(self):
        """Test encryption/decryption of large data"""
        large_data = os.urandom(1024 * 1024)  # 1MB of random data
        secure_msg = self.crypto.encrypt(large_data, self.test_key)
        decrypted = self.crypto.decrypt(secure_msg, self.test_key)
        self.assertEqual(large_data, decrypted)

if __name__ == '__main__':
    unittest.main() 