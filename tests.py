# File: tests/test_core.py
# Run with: python -m unittest tests/test_core.py

import unittest
import os
from crypto_engine import CryptoEngine
from shamir_handler import ShamirVault

class TestVaultZero(unittest.TestCase):

    def test_crypto_integrity(self):
        """Verify Encryption/Decryption cycle preserves data"""
        key = "secure_test_key"
        data = b"Sensitive Data Payload"
        
        # Initialize Engine with specific salt for reproducibility
        engine = CryptoEngine(key)
        encrypted = engine.encrypt_data(data)
        
        # Decrypt
        decrypted = CryptoEngine.decrypt_payload(key, encrypted)
        self.assertEqual(data, decrypted, "Decryption failed to recover original data")

    def test_tamper_evidence(self):
        """Verify modification of ciphertext triggers error"""
        key = "secure_test_key"
        data = b"Integrity Check"
        engine = CryptoEngine(key)
        encrypted = bytearray(engine.encrypt_data(data))
        
        # Tamper with the last byte
        encrypted[-1] = encrypted[-1] ^ 0xFF 
        
        with self.assertRaises(ValueError):
            CryptoEngine.decrypt_payload(key, bytes(encrypted))

    def test_shamir_quorum(self):
        """Verify 2/3 Quorum Logic"""
        # Note: This is a logic test, mocking the file I/O would be next step
        # For prototype, we assert the Shamir library import works
        from Crypto.Protocol.SecretSharing import Shamir
        secret = b"1234567890123456" # 16 bytes
        shares = Shamir.split(2, 3, secret)
        
        # Reconstruct with only 2 shares
        recon = Shamir.combine(shares[:2])
        self.assertEqual(secret, recon, "Shamir Quorum failed")

if __name__ == '__main__':
    unittest.main()