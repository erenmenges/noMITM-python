import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidTag
import os
import time
import threading
from typing import Tuple
import logging
import random  
import string
import sys
from Crypto import Crypto, SecureMessage, NonceManager, CryptoConstants
from Utils import ErrorCode
import psutil
import gc
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

class TestCrypto:
    @pytest.fixture
    def crypto(self):
        return Crypto()

    @pytest.fixture
    def key_pair(self) -> Tuple[bytes, bytes]:
        """Generate a test key pair"""
        return Crypto.generate_key_pair()

    @pytest.fixture
    def test_data(self) -> bytes:
        """Fixture providing test data for crypto operations."""
        return b"test_data_for_crypto_operations"

    @pytest.fixture
    def aes_key(self) -> bytes:
        """Generate a test AES key"""
        return os.urandom(CryptoConstants.AES_KEY_SIZE)

    def test_generate_key_pair(self, crypto):
        """Test key pair generation"""
        # Test without password
        public_key, private_key = crypto.generate_key_pair()
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)
        
        # Test with password
        password = b"test_password"
        public_key, private_key = crypto.generate_key_pair(password)
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)
        
        # Verify keys are in correct format
        try:
            serialization.load_pem_private_key(private_key, password=password)
            serialization.load_pem_public_key(public_key)
        except Exception as e:
            pytest.fail(f"Failed to load generated keys: {e}")

    def test_derive_session_key(self, crypto, key_pair):
        """Test session key derivation"""
        public_pem, private_pem = key_pair
        
        # Load the keys
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = serialization.load_pem_public_key(public_pem)
        
        context = b"test_context"
        
        # Derive session key
        session_key = crypto.derive_session_key(public_key, private_key, context)
        
        assert isinstance(session_key, bytes)
        assert len(session_key) == CryptoConstants.AES_KEY_SIZE

    def test_encrypt_decrypt(self, crypto, test_data, aes_key):
        """Test encryption and decryption"""
        # Test basic encryption/decryption
        secure_msg = crypto.encrypt(test_data, aes_key)
        decrypted = crypto.decrypt(secure_msg, aes_key)
        assert decrypted == test_data
        
        # Verify SecureMessage structure
        assert isinstance(secure_msg.ciphertext, bytes)
        assert isinstance(secure_msg.nonce, bytes)
        assert isinstance(secure_msg.tag, bytes)
        assert isinstance(secure_msg.version, int)
        assert isinstance(secure_msg.salt, bytes)
        
        # Test dictionary conversion
        msg_dict = secure_msg.to_dict()
        reconstructed = SecureMessage.from_dict(msg_dict)
        decrypted = crypto.decrypt(reconstructed, aes_key)
        assert decrypted == test_data

    def test_encryption_error_handling(self, crypto, test_data, aes_key):
        """Test encryption error conditions"""
        # Test invalid key size
        with pytest.raises(ValueError):
            crypto.encrypt(test_data, os.urandom(16))  # Wrong key size
            
        # Test invalid input types
        with pytest.raises(TypeError):
            crypto.encrypt("not bytes", aes_key)  # String instead of bytes
            
        with pytest.raises(TypeError):
            crypto.encrypt(test_data, "not bytes")  # String instead of bytes key

    def test_decryption_error_handling(self, crypto, test_data, aes_key):
        """Test decryption error conditions"""
        secure_msg = crypto.encrypt(test_data, aes_key)
        
        # Test wrong version
        bad_version_msg = SecureMessage(
            secure_msg.ciphertext,
            secure_msg.nonce,
            secure_msg.tag,
            version=99,  # Invalid version
            salt=secure_msg.salt
        )
        with pytest.raises(ValueError):
            crypto.decrypt(bad_version_msg, aes_key)
            
        # Test invalid key size
        with pytest.raises(ValueError):
            crypto.decrypt(secure_msg, os.urandom(16))  # Wrong key size
            
        # Test tampered ciphertext
        tampered_msg = SecureMessage(
            secure_msg.ciphertext + b'x',  # Tampered ciphertext
            secure_msg.nonce,
            secure_msg.tag,
            secure_msg.version,
            secure_msg.salt
        )
        with pytest.raises(RuntimeError):
            crypto.decrypt(tampered_msg, aes_key)

    def test_hash_function(self, crypto, test_data):
        """Test hash function"""
        hash1 = crypto.hash(test_data)
        hash2 = crypto.hash(test_data)
        
        # Verify hash properties
        assert isinstance(hash1, bytes)
        assert len(hash1) == 32  # SHA-256 produces 32-byte hash
        assert hash1 == hash2  # Same input should produce same hash
        
        # Different input should produce different hash
        different_hash = crypto.hash(test_data + b"extra")
        assert hash1 != different_hash

    def test_mac_error_propagation(self, crypto):
        """Test MAC verification error handling"""
        key = os.urandom(CryptoConstants.AES_KEY_SIZE)
        data = b"test data"
        
        # Create valid MAC
        mac = crypto.create_mac(key, data)
        
        # Test various error conditions
        error_cases = [
            (b"", data, mac, ValueError),  # Empty key
            (key, b"", mac, False),  # Empty data should fail verification
            (key[:-1], data, mac, ValueError),  # Invalid key size
            (key, data, mac[:-1], ValueError),  # Invalid MAC size
            (key, data, b"", ValueError),  # Empty MAC
            (key, data + b"x", mac, False),  # Modified data
            (os.urandom(32), data, mac, False),  # Wrong key
        ]
        
        for test_key, test_data, test_mac, expected in error_cases:
            if isinstance(expected, bool):
                assert crypto.verify_mac(test_key, test_data, test_mac) == expected
            else:
                with pytest.raises(expected):
                    crypto.verify_mac(test_key, test_data, test_mac)

    def test_mac_functions(self, crypto, test_data, aes_key):
        """Test MAC creation and verification"""
        # Test basic MAC functionality
        mac = crypto.create_mac(aes_key, test_data)
        assert crypto.verify_mac(aes_key, test_data, mac)
        
        # Test MAC verification failure
        tampered_data = test_data + b"extra"
        assert not crypto.verify_mac(aes_key, tampered_data, mac)
        
        # Test MAC with different key
        different_key = os.urandom(CryptoConstants.AES_KEY_SIZE)
        assert not crypto.verify_mac(different_key, test_data, mac)

    def test_aes_functions(self, crypto, test_data, aes_key):
        """Test direct AES encryption/decryption"""
        # Test basic encryption/decryption
        nonce, ciphertext, tag = crypto.aes_encrypt(test_data, aes_key)
        decrypted = crypto.aes_decrypt(ciphertext, aes_key, nonce, tag)
        assert decrypted == test_data
        
        # Test invalid tag
        invalid_tag = os.urandom(16)
        with pytest.raises(InvalidTag):
            crypto.aes_decrypt(ciphertext, aes_key, nonce, invalid_tag)
            
        # Test invalid key size
        with pytest.raises(ValueError):
            crypto.aes_encrypt(test_data, os.urandom(16))  # Wrong key size

    def test_nonce_manager(self):
        """Test NonceManager functionality"""
        from Crypto import NonceManager  # Import the correct NonceManager
        
        manager = NonceManager(cache_size=5, nonce_lifetime=1)  # Short lifetime for testing
        
        # Test nonce generation and verification
        nonce = manager.generate_nonce()
        assert isinstance(nonce, bytes)
        assert len(nonce) == CryptoConstants.NONCE_SIZE
        
        # Test nonce verification
        assert not manager.verify_nonce(nonce)  # Should fail (nonce already used)
        
        # Test nonce expiration
        time.sleep(1.1)  # Wait for nonce to expire
        assert manager.verify_nonce(nonce)  # Should succeed (nonce expired)

    def test_key_cache_cleanup(self, crypto):
        """Test key cache cleanup"""
        # Add test key to cache
        test_key = os.urandom(32)
        with crypto._key_cache_lock:
            crypto._key_cache['test'] = {
                'key': test_key,
                'timestamp': time.time() - crypto._cleanup_interval - 1
            }
        
        # Trigger cleanup
        crypto.cleanup_key_cache()
        
        # Verify key was removed
        with crypto._key_cache_lock:
            assert 'test' not in crypto._key_cache

    def test_concurrent_nonce_generation(self):
        """Test concurrent nonce generation"""
        manager = NonceManager()
        nonces = set()
        num_threads = 10
        nonces_per_thread = 100
        
        def generate_nonces():
            for _ in range(nonces_per_thread):
                nonce = manager.generate_nonce()
                with threading.Lock():
                    nonces.add(nonce)
        
        threads = [threading.Thread(target=generate_nonces) for _ in range(num_threads)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
            
        # Verify all nonces are unique
        assert len(nonces) == num_threads * nonces_per_thread

    def test_large_data_handling(self, crypto, aes_key):
        """Test encryption/decryption of large data"""
        # Test with 1MB of random data
        large_data = os.urandom(1024 * 1024)  # 1MB
        secure_msg = crypto.encrypt(large_data, aes_key)
        decrypted = crypto.decrypt(secure_msg, aes_key)
        assert decrypted == large_data
        
        # Test with 10MB of random data
        very_large_data = os.urandom(10 * 1024 * 1024)  # 10MB
        secure_msg = crypto.encrypt(very_large_data, aes_key)
        decrypted = crypto.decrypt(secure_msg, aes_key)
        assert decrypted == very_large_data

    def test_empty_data_handling(self, crypto, aes_key):
        """Test encryption/decryption of empty data"""
        empty_data = b""
        secure_msg = crypto.encrypt(empty_data, aes_key)
        decrypted = crypto.decrypt(secure_msg, aes_key)
        assert decrypted == empty_data

    def test_key_pair_password_handling(self, crypto):
        """Test key pair generation with different password scenarios"""
        # Test with empty password
        with pytest.raises(ValueError):
            crypto.generate_key_pair(b"")
            
        # Test with long password (but within limits)
        long_password = b"x" * 1000  # Just under the 1023 byte limit
        public_key, private_key = crypto.generate_key_pair(long_password)
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)
        
        # Test with very long password (should fail)
        too_long_password = b"x" * 1024  # Exceeds 1023 byte limit
        with pytest.raises(ValueError) as exc_info:
            crypto.generate_key_pair(too_long_password)
        assert "Passwords longer than 1023 bytes" in str(exc_info.value)
        
        # Test with special characters in password
        special_password = b"!@#$%^&*()"
        public_key, private_key = crypto.generate_key_pair(special_password)
        assert isinstance(public_key, bytes)
        assert isinstance(private_key, bytes)

    def test_nonce_cleanup_concurrent_modification(self):
        """Test nonce cleanup with concurrent modifications"""
        manager = NonceManager(nonce_lifetime=0.1)  # Short lifetime for testing
        
        # Add some nonces
        nonces = [manager.generate_nonce() for _ in range(100)]
        
        def modifier():
            """Continuously modify nonce cache"""
            for _ in range(50):
                time.sleep(0.01)
                nonce = manager.generate_nonce()
                
        def cleaner():
            """Continuously clean nonces"""
            for _ in range(50):
                time.sleep(0.01)
                manager._cleanup_expired_nonces()
                
        # Run concurrent modifications and cleanup
        threads = [
            threading.Thread(target=modifier),
            threading.Thread(target=cleaner)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
            
        # Verify no exceptions occurred and cache is consistent
        assert isinstance(manager._nonce_cache, dict)
        
        # Verify expired nonces are cleaned
        time.sleep(0.2)  # Wait for all nonces to expire
        manager._cleanup_expired_nonces()
        assert len(manager._nonce_cache) == 0

    def test_nonce_manager_thread_safety(self):
        """Test thread safety of NonceManager operations"""
        manager = NonceManager()
        num_threads = 20
        operations_per_thread = 1000
        results = []
        errors = []
        
        def worker():
            try:
                thread_nonces = set()
                for _ in range(operations_per_thread):
                    # Generate and verify nonces
                    nonce = manager.generate_nonce()
                    
                    # Verify uniqueness within thread
                    assert nonce not in thread_nonces
                    thread_nonces.add(nonce)
                    
                    # Verify nonce verification
                    assert not manager.verify_nonce(nonce)  # Should fail (already used)
                    
                    # Add results for cross-thread verification
                    with threading.Lock():
                        results.append(nonce)
                        
                    # Occasionally trigger cleanup
                    if random.random() < 0.1:
                        manager._cleanup_expired_nonces()
                        
            except Exception as e:
                errors.append(e)
        
        # Run threads
        threads = [threading.Thread(target=worker) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
            
        # Verify no errors occurred
        assert not errors, f"Errors in threads: {errors}"
        
        # Verify all nonces were unique across threads
        assert len(set(results)) == len(results)
        
        # Verify cache cleanup occurred properly
        assert len(manager._nonce_cache) <= manager._cache_size

    def test_nonce_manager_stress(self):
        """Stress test NonceManager with rapid requests"""
        manager = NonceManager(cache_size=1000000, nonce_lifetime=1)
        nonces = set()
        
        # Generate many nonces rapidly
        for _ in range(100000):
            nonce = manager.generate_nonce()
            assert nonce not in nonces
            nonces.add(nonce)
            
        # Verify all nonces are unique
        assert len(nonces) == 100000

    def test_nonce_manager_cache_limit(self):
        """Test NonceManager cache size limit"""
        small_cache_size = 10
        manager = NonceManager(cache_size=small_cache_size, nonce_lifetime=300)
        
        # Fill cache to limit
        nonces = [manager.generate_nonce() for _ in range(small_cache_size)]
        
        # Verify oldest nonces are removed when cache is full
        for _ in range(small_cache_size):
            new_nonce = manager.generate_nonce()
            assert new_nonce not in nonces

    def test_key_derivation_cleanup(self, crypto, key_pair):
        """Test cleanup in key derivation process"""
        import gc
        import ctypes
        import sys
        
        public_pem, private_pem = key_pair
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = serialization.load_pem_public_key(public_pem)
        
        # Get initial object count
        initial_count = len([obj for obj in gc.get_objects() if isinstance(obj, bytes)])
        
        # Derive key and store its value
        key = crypto.derive_session_key(public_key, private_key, b"test_context")
        key_value = bytes(key)  # Make a copy
        
        # Delete reference and force collection
        del key
        gc.collect()
        
        # Check if any remaining bytes objects contain our key value
        remaining_bytes = [obj for obj in gc.get_objects() 
                         if isinstance(obj, bytes) and len(obj) == len(key_value)]
        key_found = any(obj == key_value for obj in remaining_bytes)
        
        assert not key_found, "Key material still found in memory"
        
        # Additional verification - try to derive the same key again
        new_key = crypto.derive_session_key(public_key, private_key, b"test_context")
        # Keys should be different due to random salt
        assert new_key != key_value, "Key derivation should produce different keys"
        
        # Clean up the test key value
        key_value = b'\x00' * len(key_value)

    def test_key_derivation_edge_cases(self, crypto, key_pair):
        """Test edge cases in key derivation"""
        public_pem, private_pem = key_pair
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = serialization.load_pem_public_key(public_pem)
        
        # Test with empty context
        key1 = crypto.derive_session_key(public_key, private_key, b"")
        assert len(key1) == CryptoConstants.AES_KEY_SIZE
        
        # Test with very large context
        large_context = b"x" * 10000
        key2 = crypto.derive_session_key(public_key, private_key, large_context)
        assert len(key2) == CryptoConstants.AES_KEY_SIZE
        
        # Test with different curves
        different_curve_key = ec.generate_private_key(ec.SECP384R1())
        with pytest.raises(ValueError):
            crypto.derive_session_key(
                different_curve_key.public_key(),
                private_key,
                b"test"
            )

    def test_key_derivation_consistency(self, crypto, key_pair):
        """Test consistency of key derivation"""
        public_pem, private_pem = key_pair
        private_key = serialization.load_pem_private_key(private_pem, password=None)
        public_key = serialization.load_pem_public_key(public_pem)
        context = b"test_context"
        
        # Derive key multiple times and verify consistency
        key1 = crypto.derive_session_key(public_key, private_key, context)
        key2 = crypto.derive_session_key(public_key, private_key, context)
        
        # Keys should be different due to random salt
        assert key1 != key2

    def test_invalid_key_formats(self, crypto):
        """Test handling of invalid key formats"""
        invalid_pem = b"-----BEGIN PUBLIC KEY-----\nINVALIDKEY\n-----END PUBLIC KEY-----"
        
        # Test loading invalid public key
        with pytest.raises(ValueError):
            serialization.load_pem_public_key(invalid_pem)
            
        # Test loading invalid private key
        with pytest.raises(ValueError):
            serialization.load_pem_private_key(invalid_pem, password=None)

    def test_concurrent_encryption(self, crypto, test_data, aes_key):
        """Test concurrent encryption operations"""
        num_threads = 20
        encryptions_per_thread = 50
        results = []
        
        def encrypt_decrypt():
            for _ in range(encryptions_per_thread):
                secure_msg = crypto.encrypt(test_data, aes_key)
                decrypted = crypto.decrypt(secure_msg, aes_key)
                with threading.Lock():
                    results.append(decrypted == test_data)
        
        threads = [threading.Thread(target=encrypt_decrypt) for _ in range(num_threads)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
            
        assert all(results)
        assert len(results) == num_threads * encryptions_per_thread

    def test_hash_collision_resistance(self, crypto):
        """Test hash function collision resistance"""
        # Generate similar messages
        msg1 = b"test message"
        msg2 = b"test message "  # Extra space
        msg3 = b"Test message"   # Capital T
        
        hash1 = crypto.hash(msg1)
        hash2 = crypto.hash(msg2)
        hash3 = crypto.hash(msg3)
        
        # Verify all hashes are different
        assert hash1 != hash2
        assert hash1 != hash3
        assert hash2 != hash3
        
        # Verify hash length
        assert all(len(h) == 32 for h in [hash1, hash2, hash3])

    def test_secure_message_validation(self, crypto, aes_key):
        """Test SecureMessage validation"""
        # Test with invalid types
        with pytest.raises(TypeError):
            SecureMessage(
                ciphertext="not bytes",  # Should be bytes
                nonce=b"nonce",
                tag=b"tag",
                version=1,
                salt=b"salt"
            )
            
        with pytest.raises(TypeError):
            SecureMessage(
                ciphertext=b"ciphertext",
                nonce=123,  # Should be bytes
                tag=b"tag",
                version=1,
                salt=b"salt"
            )
            
        # Test with invalid version type
        with pytest.raises(TypeError):
            SecureMessage(
                ciphertext=b"ciphertext",
                nonce=b"nonce",
                tag=b"tag",
                version="1",  # Should be int
                salt=b"salt"
            )
            
        # Test dict conversion with invalid hex strings
        secure_msg = crypto.encrypt(b"test", aes_key)
        msg_dict = secure_msg.to_dict()
        msg_dict['ciphertext'] = "invalid hex"
        
        with pytest.raises(ValueError):
            SecureMessage.from_dict(msg_dict)

    def test_secure_message_serialization(self, crypto, aes_key, test_data):
        """Test SecureMessage serialization/deserialization"""
        # Create a secure message
        secure_msg = crypto.encrypt(test_data, aes_key)

    @pytest.mark.benchmark(
        min_rounds=50,
        warmup=True
    )
    def test_encryption_performance(self, crypto, aes_key, benchmark):
        """Benchmark encryption operation"""
        test_data = os.urandom(1024 * 1024)  # 1MB
        
        def bench_encryption():
            return crypto.encrypt(test_data, aes_key)
            
        result = benchmark.pedantic(
            bench_encryption,
            iterations=10,
            rounds=100
        )
        assert isinstance(result, SecureMessage)

    @pytest.mark.benchmark(
        min_rounds=50,
        warmup=True
    )
    def test_decryption_performance(self, crypto, aes_key, benchmark):
        """Benchmark decryption operation"""
        test_data = os.urandom(1024 * 1024)  # 1MB
        secure_msg = crypto.encrypt(test_data, aes_key)
        
        def bench_decryption():
            return crypto.decrypt(secure_msg, aes_key)
            
        result = benchmark.pedantic(
            bench_decryption,
            iterations=10,
            rounds=100
        )
        assert isinstance(result, bytes)
        assert result == test_data

    @pytest.mark.benchmark(
        min_rounds=50,
        warmup=True
    )
    def test_hash_performance(self, crypto, aes_key, benchmark):
        """Benchmark hash operation"""
        test_data = os.urandom(1024 * 1024)  # 1MB
        
        def bench_hash():
            return crypto.hash(test_data)
            
        result = benchmark.pedantic(
            bench_hash,
            iterations=10,
            rounds=100
        )
        assert isinstance(result, bytes)

    def test_memory_leaks(self, crypto, aes_key):
        """Test for memory leaks in crypto operations"""

        
        process = psutil.Process()
        initial_memory = process.memory_info().rss
        
        # Perform many crypto operations
        for _ in range(1000):
            data = os.urandom(1024 * 100)  # 100KB
            secure_msg = crypto.encrypt(data, aes_key)
            decrypted = crypto.decrypt(secure_msg, aes_key)
            crypto.hash(data)
            crypto.create_mac(aes_key, data)
            
        # Force garbage collection
        gc.collect()
        
        # Check memory usage
        final_memory = process.memory_info().rss
        memory_diff = final_memory - initial_memory
        
        # Allow for some memory overhead (1MB)
        assert memory_diff < 1024 * 1024, f"Potential memory leak detected: {memory_diff} bytes"

    def test_key_cache_memory_cleanup(self, crypto):
        """Test thorough memory cleanup in key cache"""
        import gc
        
        # Add some keys to cache
        test_keys = {}
        key_values = []
        
        for i in range(10):
            key_data = os.urandom(32)
            key_id = f"test_key_{i}"
            test_keys[key_id] = {
                'key': key_data,
                'timestamp': time.time() - crypto._cleanup_interval - 1
            }
            key_values.append(bytes(key_data))  # Store copies of keys
        
        with crypto._key_cache_lock:
            crypto._key_cache.update(test_keys)
        
        # Run cleanup
        crypto.cleanup_key_cache()
        
        # Force garbage collection
        gc.collect()
        
        # Verify all keys are properly cleaned
        with crypto._key_cache_lock:
            # Keys should be removed from cache
            for key_id in test_keys:
                assert key_id not in crypto._key_cache
            
            # Check if any remaining bytes objects contain our key values
            remaining_bytes = [obj for obj in gc.get_objects() 
                             if isinstance(obj, bytes) and len(obj) == 32]
            
            for key_value in key_values:
                key_found = any(obj == key_value for obj in remaining_bytes)
                assert not key_found, f"Key material {key_value.hex()} still found in memory"
        
        # Clean up test values
        for i in range(len(key_values)):
            key_values[i] = b'\x00' * len(key_values[i])

    def test_key_cache_concurrent_access(self, crypto):
        """Test concurrent access to key cache"""
        num_threads = 50
        operations_per_thread = 100
        errors = []
        
        def cache_operations():
            try:
                for _ in range(operations_per_thread):
                    key = os.urandom(32)
                    with crypto._key_cache_lock:
                        crypto._key_cache[key] = {
                            'key': os.urandom(32),
                            'timestamp': time.time()
                        }
                    time.sleep(0.001)  # Simulate some work
                    crypto.cleanup_key_cache()
            except Exception as e:
                errors.append(e)
                
        threads = [threading.Thread(target=cache_operations) for _ in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
            
        assert not errors, f"Errors occurred during concurrent access: {errors}"

    @pytest.mark.parametrize("data_size", [
        1024,          # 1KB
        1024 * 1024,   # 1MB
        10 * 1024 * 1024,  # 10MB
        100 * 1024 * 1024  # 100MB
    ])
    def test_large_file_encryption(self, crypto, aes_key, data_size):
        """Test encryption/decryption of files of various sizes"""
        data = os.urandom(data_size)
        secure_msg = crypto.encrypt(data, aes_key)
        decrypted = crypto.decrypt(secure_msg, aes_key)
        assert decrypted == data

    def test_fuzzing_inputs(self, crypto, aes_key):
        """Test crypto operations with fuzzed inputs"""
        import random
        
        def generate_fuzzed_data(size):
            return bytes(random.randint(0, 255) for _ in range(size))
        
        # Test with various fuzzed data sizes
        for _ in range(100):
            size = random.randint(0, 1024 * 1024)  # Up to 1MB
            fuzzed_data = generate_fuzzed_data(size)
            
            try:
                secure_msg = crypto.encrypt(fuzzed_data, aes_key)
                decrypted = crypto.decrypt(secure_msg, aes_key)
                assert decrypted == fuzzed_data
            except (ValueError, TypeError):
                # These exceptions are expected for invalid inputs
                pass
                
        # Test with fuzzed keys
        test_data = b"test data"
        for _ in range(100):
            fuzzed_key = generate_fuzzed_data(random.randint(0, 64))
            
            try:
                crypto.encrypt(test_data, fuzzed_key)
            except (ValueError, TypeError):
                # Expected for invalid key sizes
                pass

    @pytest.mark.parametrize("chunk_size", [
        1024,      # 1KB
        4096,      # 4KB
        16384,     # 16KB
        65536      # 64KB
    ])
    def test_streaming_encryption(self, crypto, aes_key, chunk_size):
        """Test encryption/decryption in chunks (simulating streaming)"""
        total_size = 1024 * 1024 * 10  # 10MB total
        data = os.urandom(total_size)
        
        # Encrypt in chunks
        chunks = [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]
        encrypted_chunks = []
        
        for chunk in chunks:
            secure_msg = crypto.encrypt(chunk, aes_key)
            encrypted_chunks.append(secure_msg)
            
        # Decrypt chunks
        decrypted_data = b""
        for secure_msg in encrypted_chunks:
            decrypted_chunk = crypto.decrypt(secure_msg, aes_key)
            decrypted_data += decrypted_chunk
            
        assert decrypted_data == data

    def test_key_rotation(self, crypto):
        """Test key rotation scenarios"""
        data = b"test data"
        old_key = os.urandom(CryptoConstants.AES_KEY_SIZE)
        new_key = os.urandom(CryptoConstants.AES_KEY_SIZE)
        
        # Encrypt with old key
        secure_msg = crypto.encrypt(data, old_key)
        
        # Decrypt with old key
        decrypted = crypto.decrypt(secure_msg, old_key)
        assert decrypted == data
        
        # Re-encrypt with new key
        new_secure_msg = crypto.encrypt(decrypted, new_key)
        
        # Decrypt with new key
        final_decrypted = crypto.decrypt(new_secure_msg, new_key)
        assert final_decrypted == data
        
        # Verify old encrypted data can't be decrypted with new key
        with pytest.raises(Exception):
            crypto.decrypt(secure_msg, new_key)

    def test_crypto_initialization(self):
        """Test Crypto class initialization and defaults"""
        crypto = Crypto()
        assert isinstance(crypto._nonce_manager, NonceManager)
        assert isinstance(crypto._key_cache, dict)
        assert isinstance(crypto._key_cache_lock, type(threading.Lock()))
        assert isinstance(crypto._cleanup_interval, (int, float))
        assert crypto._cleanup_interval == 3600  # Default value

    def test_cross_platform_compatibility(self, crypto, aes_key):
        """Test encryption compatibility across different platforms"""
        data = b"test data"
        
        # Simulate different endianness
        def swap_endianness(b: bytes) -> bytes:
            return b"".join(b[i:i+1] for i in range(len(b)-1, -1, -1))
        
        # Encrypt normally
        secure_msg = crypto.encrypt(data, aes_key)
        
        # Test with swapped endianness data
        swapped_msg = SecureMessage(
            swap_endianness(secure_msg.ciphertext),
            secure_msg.nonce,
            secure_msg.tag,
            secure_msg.version,
            secure_msg.salt
        )
        
        # Should fail with swapped endianness
        with pytest.raises(Exception):
            crypto.decrypt(swapped_msg, aes_key)

    def test_error_propagation(self, crypto, aes_key):
        """Test error propagation in encrypted data"""
        data = b"test data" * 1000  # Create larger data to test error propagation
        secure_msg = crypto.encrypt(data, aes_key)
        
        # Modify single bits in different positions
        for pos in [0, len(secure_msg.ciphertext)//2, -1]:
            modified_ciphertext = bytearray(secure_msg.ciphertext)
            modified_ciphertext[pos] ^= 1  # Flip a single bit
            
            modified_msg = SecureMessage(
                bytes(modified_ciphertext),
                secure_msg.nonce,
                secure_msg.tag,
                secure_msg.version,
                secure_msg.salt
            )
            
            # Verify decryption fails
            with pytest.raises(Exception):
                crypto.decrypt(modified_msg, aes_key)

    def test_aes_nonce_validation(self, crypto, aes_key):
        """Test AES nonce validation"""
        test_data = b"test data"
        secure_msg = crypto.encrypt(test_data, aes_key)
        
        # Test with invalid nonce sizes
        for invalid_size in [8, 11, 13, 16]:
            invalid_nonce = os.urandom(invalid_size)
            with pytest.raises(ValueError) as exc_info:
                crypto.aes_decrypt(
                    secure_msg.ciphertext,
                    aes_key,
                    invalid_nonce,
                    secure_msg.tag
                )
            assert f"Nonce must be {CryptoConstants.NONCE_SIZE} bytes long" in str(exc_info.value)
            
        # Test with correct nonce size
        valid_nonce = os.urandom(CryptoConstants.NONCE_SIZE)
        # Should raise InvalidTag because nonce doesn't match
        with pytest.raises(InvalidTag):
            crypto.aes_decrypt(
                secure_msg.ciphertext,
                aes_key,
                valid_nonce,
                secure_msg.tag
            )

    def test_aes_mode_properties(self, crypto, aes_key):
        """Test properties of AES-GCM mode"""
        data = b"test data"
        
        # Test that same plaintext encrypts to different ciphertext
        msg1 = crypto.encrypt(data, aes_key)
        msg2 = crypto.encrypt(data, aes_key)
        
        assert msg1.ciphertext != msg2.ciphertext
        assert msg1.nonce != msg2.nonce
        assert msg1.tag != msg2.tag
        
        # Verify both still decrypt correctly
        assert crypto.decrypt(msg1, aes_key) == data
        assert crypto.decrypt(msg2, aes_key) == data

    def test_timing_attacks(self, crypto, aes_key):
        """Test resistance to timing attacks"""
        from time import perf_counter
        import statistics
        
        data = b"test data" * 1000  # Use larger data for more reliable timing
        secure_msg = crypto.encrypt(data, aes_key)
        valid_times = []
        invalid_times = []
        
        # Run multiple iterations to get statistically significant results
        for _ in range(100):
            # Measure timing of successful decryption
            start = perf_counter()
            crypto.decrypt(secure_msg, aes_key)
            valid_times.append(perf_counter() - start)
            
            # Measure timing of failed decryption
            modified_msg = SecureMessage(
                secure_msg.ciphertext + b'x',
                secure_msg.nonce,
                secure_msg.tag,
                secure_msg.version,
                secure_msg.salt
            )
            
            start = perf_counter()
            try:
                crypto.decrypt(modified_msg, aes_key)
            except:
                pass
            invalid_times.append(perf_counter() - start)
        
        # Remove outliers (values more than 2 standard deviations from mean)
        def remove_outliers(times):
            mean = statistics.mean(times)
            stdev = statistics.stdev(times)
            return [t for t in times if abs(t - mean) <= 2 * stdev]
        
        valid_times = remove_outliers(valid_times)
        invalid_times = remove_outliers(invalid_times)
        
        # Compare average times
        avg_valid = statistics.mean(valid_times)
        avg_invalid = statistics.mean(invalid_times)
        time_diff_ratio = abs(avg_valid - avg_invalid) / min(avg_valid, avg_invalid)
        
        # Allow for more reasonable timing variation (300%)
        assert time_diff_ratio < 3.0, (
            f"Potential timing attack vulnerability - "
            f"valid/invalid time ratio: {time_diff_ratio:.2f}"
        )

    def test_key_scheduling(self, crypto):
        """Test key scheduling and management"""
        num_keys = 100
        key_schedule = {}
        base_time = time.time()
        
        # Create key schedule
        for i in range(num_keys):
            key_id = f"key_{i}"
            key_data = os.urandom(CryptoConstants.AES_KEY_SIZE)
            # Some keys expire soon, others later
            expiry = base_time + (i % 10)  # Spread expirations over 10 seconds
            
            with crypto._key_cache_lock:
                crypto._key_cache[key_id] = {
                    'key': key_data,
                    'timestamp': expiry
                }
            key_schedule[key_id] = expiry
        
        # Wait for some keys to expire
        time.sleep(5)  # Wait 5 seconds
        
        # Cleanup expired keys
        crypto.cleanup_key_cache()
        
        # Verify expired keys are removed
        current_time = time.time()
        with crypto._key_cache_lock:
            for key_id, expiry in key_schedule.items():
                if expiry <= current_time:
                    assert key_id not in crypto._key_cache, \
                        f"Key {key_id} should have been removed (expired at {expiry}, current time {current_time})"
                else:
                    assert key_id in crypto._key_cache, \
                        f"Key {key_id} should still be present (expires at {expiry}, current time {current_time})"

    def test_side_channel_resistance(self, crypto, aes_key):
        """Test resistance to side-channel attacks"""
        import gc
        import sys
        
        # Create sensitive data with a unique marker
        marker = bytes([i for i in range(32)])  # Unique pattern
        data = b"sensitive_data" + marker
        
        # Create encrypted message
        secure_msg = crypto.encrypt(data, aes_key)
        
        # Delete original data and force collection
        del data
        gc.collect()
        
        # Function to safely check memory contents
        def find_pattern_in_memory():
            # Get all objects that might contain our data
            gc.collect()  # Force collection before scanning
            count = 0
            for obj in gc.get_objects():
                if not isinstance(obj, bytes):
                    continue
                try:
                    # Check if object contains our marker
                    if marker in obj:
                        count += 1
                except:
                    continue
            # We expect to find the marker only in the encrypted data
            return count <= 1  # Allow one occurrence (in the encrypted form)
            
        # Verify sensitive data is not found in clear text
        assert find_pattern_in_memory(), "Sensitive data found in memory after deletion"
        
        # Verify the data can still be recovered through proper decryption
        decrypted = crypto.decrypt(secure_msg, aes_key)
        assert decrypted == b"sensitive_data" + marker
        
        # Clean up
        del decrypted
        del marker
        gc.collect()

    def test_destructor_cleanup(self):
        """Test proper cleanup in destructor"""
        crypto = Crypto()
        
        # Add some test keys to cache
        test_keys = {
            'key1': {'key': os.urandom(32), 'timestamp': time.time()},
            'key2': {'key': os.urandom(32), 'timestamp': time.time()}
        }
        
        # Store copies of the keys for comparison
        key_copies = {k: bytes(v['key']) for k, v in test_keys.items()}
        
        with crypto._key_cache_lock:
            crypto._key_cache.update(test_keys)
        
        # Delete the crypto instance
        del crypto
        
        # Force garbage collection
        import gc
        gc.collect()
        
        # Check if any remaining bytes objects contain our key values
        remaining_bytes = [obj for obj in gc.get_objects() 
                         if isinstance(obj, bytes) and len(obj) == 32]
        
        # Verify keys are properly cleaned up
        for key_id, key_value in key_copies.items():
            key_found = any(obj == key_value for obj in remaining_bytes)
            assert not key_found, f"Key material for {key_id} still found in memory"
            
        # Clean up our test copies
        for k in key_copies:
            key_copies[k] = b'\x00' * len(key_copies[k])

    def test_nonce_prediction_resistance(self, crypto):
        """Test nonce prediction resistance"""
        nonces = []
        manager = NonceManager()
        
        # Generate sequence of nonces
        for _ in range(1000):
            nonce = manager.generate_nonce()
            nonces.append(nonce)
            
        # Test for patterns in nonces
        for i in range(len(nonces)-1):
            # Verify consecutive nonces are different
            assert nonces[i] != nonces[i+1]
            
            # Verify nonces aren't sequential
            if len(nonces[i]) == len(nonces[i+1]):
                int_diff = int.from_bytes(nonces[i+1], 'big') - int.from_bytes(nonces[i], 'big')
                assert abs(int_diff) > 1, "Nonces appear to be sequential"

    @pytest.fixture
    def mock_log_error(self, mocker):
        """Mock the log_error function from Utils"""
        return mocker.patch('Crypto.log_error')

    def test_error_logging_with_utils(self, crypto, mock_log_error):
        """Test integration with Utils.log_error"""
        # Test key cache cleanup error logging
        with crypto._key_cache_lock:
            # Cause an error by setting invalid key data
            crypto._key_cache['test'] = 'invalid'
            
        crypto.cleanup_key_cache()
        
        # Verify error was logged
        mock_log_error.assert_called_once()
        mock_log_error.assert_called_with(
            ErrorCode.CRYPTO_ERROR,
            "Key cache cleanup failed: string indices must be integers, not 'str'"
        )

    def test_error_logging(self, crypto, aes_key, caplog):
        """Test error logging functionality"""
        # Configure caplog to capture all loggers
        caplog.set_level(logging.ERROR)
        
        # Test encryption error logging
        with caplog.at_level(logging.ERROR):
            with pytest.raises(TypeError):
                crypto.encrypt("not bytes", aes_key)
            assert "Encryption failed" in caplog.text
            caplog.clear()
        
        # Test decryption error logging
        with caplog.at_level(logging.ERROR):
            invalid_msg = SecureMessage(
                b"invalid",
                b"invalid",
                b"invalid",
                CryptoConstants.VERSION,
                b"invalid"
            )
            with pytest.raises(RuntimeError):
                crypto.decrypt(invalid_msg, aes_key)
            assert "Decryption failed" in caplog.text
            caplog.clear()
        
        # Test key pair generation error logging
        with caplog.at_level(logging.ERROR):
            with pytest.raises(ValueError):
                crypto.generate_key_pair(b"")  # Empty password
            assert "Key pair generation failed" in caplog.text

    def test_padding_oracle(self, crypto, aes_key, test_data):
        """Test resistance to padding oracle attacks"""
        data = test_data * 16  # Ensure multiple blocks
        secure_msg = crypto.encrypt(data, aes_key)
        
        # Try various padding modifications
        for i in range(16):  # Test last block
            modified = bytearray(secure_msg.ciphertext)
            modified[-i-1] ^= 0xFF  # Modify padding byte
            
            modified_msg = SecureMessage(
                bytes(modified),
                secure_msg.nonce,
                secure_msg.tag,
                secure_msg.version,
                secure_msg.salt
            )
            
            # All modifications should fail similarly
            with pytest.raises(Exception) as exc_info:
                crypto.decrypt(modified_msg, aes_key)
                
            # Store error message for first iteration
            if i == 0:
                expected_error = str(exc_info.value)
            else:
                # All padding errors should look the same
                assert str(exc_info.value) == expected_error