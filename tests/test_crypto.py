"""
test_crypto.py
Author: Mourya Reddy Udumula
Unit tests for AES-256-GCM encryption and PBKDF2 key derivation.
Validates: encrypt/decrypt round-trips, key derivation determinism,
GCM authentication tag verification, invalid key rejection.
"""

import sys
import os
import pytest

# Ensure VaultZero root is importable when pytest is run from tests/ subdir
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from crypto_engine import CryptoEngine


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def key():
    return "secure_test_key_for_pytest"


@pytest.fixture
def plaintext():
    return b"Sensitive Data Payload - VaultZero Unit Test"


@pytest.fixture
def encrypted(key, plaintext):
    """Pre-encrypt plaintext once; reused across tests that only need to decrypt."""
    engine = CryptoEngine(key)
    return engine.encrypt_data(plaintext)


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestEncryptDecryptRoundtrip:
    def test_basic_roundtrip(self, key, plaintext):
        """encrypt then decrypt returns the original plaintext."""
        engine = CryptoEngine(key)
        ct = engine.encrypt_data(plaintext)
        recovered = CryptoEngine.decrypt_payload(key, ct)
        assert recovered == plaintext

    def test_empty_input(self, key):
        """Encrypting empty bytes and decrypting returns empty bytes."""
        engine = CryptoEngine(key)
        ct = engine.encrypt_data(b"")
        recovered = CryptoEngine.decrypt_payload(key, ct)
        assert recovered == b""

    def test_large_payload(self, key):
        """Roundtrip succeeds for a 1 MB payload."""
        large_data = os.urandom(1024 * 1024)
        engine = CryptoEngine(key)
        ct = engine.encrypt_data(large_data)
        assert CryptoEngine.decrypt_payload(key, ct) == large_data

    @pytest.mark.parametrize("data", [
        b"x",
        b"hello world",
        b"\x00\xff\xfe\xfd",
        b"A" * 256,
    ])
    def test_various_payloads(self, key, data):
        """Roundtrip works for various payload sizes and byte patterns."""
        engine = CryptoEngine(key)
        assert CryptoEngine.decrypt_payload(key, engine.encrypt_data(data)) == data


class TestKeyDerivation:
    def test_pbkdf2_determinism(self):
        """Same password + same salt always derives the same key."""
        password = "determinism_test"
        salt = b"\xde\xad\xbe\xef" * 4  # fixed 16-byte salt
        engine1 = CryptoEngine(password, salt=salt)
        engine2 = CryptoEngine(password, salt=salt)
        assert engine1.key == engine2.key

    def test_different_salts_produce_different_keys(self):
        """Different salts with the same password produce different keys."""
        password = "same_password"
        engine1 = CryptoEngine(password)
        engine2 = CryptoEngine(password)
        # Random salts are used by default — keys should almost certainly differ
        assert engine1.salt != engine2.salt or engine1.key != engine2.key

    def test_key_length_is_32_bytes(self):
        """PBKDF2 derived key is exactly 32 bytes (256-bit AES key)."""
        engine = CryptoEngine("any_password")
        assert len(engine.key) == 32

    def test_different_passwords_different_keys(self):
        """Different passwords with the same salt produce different keys."""
        salt = b"\xab\xcd\xef\x01" * 4
        e1 = CryptoEngine("password_alpha", salt=salt)
        e2 = CryptoEngine("password_beta",  salt=salt)
        assert e1.key != e2.key


class TestGCMAuthentication:
    def test_tampered_ciphertext_raises(self, key, plaintext):
        """Flipping a byte in the ciphertext causes decrypt_and_verify to raise."""
        engine = CryptoEngine(key)
        ct = bytearray(engine.encrypt_data(plaintext))
        ct[-1] ^= 0xFF          # flip last ciphertext byte
        with pytest.raises(Exception):   # ValueError from PyCryptodome MAC check
            CryptoEngine.decrypt_payload(key, bytes(ct))

    def test_tampered_tag_raises(self, key, plaintext):
        """Flipping a byte in the GCM tag causes authentication failure."""
        engine = CryptoEngine(key)
        ct = bytearray(engine.encrypt_data(plaintext))
        # Layout: [salt:16][nonce:16][tag:16][ciphertext]
        ct[32] ^= 0x01          # flip first byte of tag
        with pytest.raises(Exception):
            CryptoEngine.decrypt_payload(key, bytes(ct))

    def test_wrong_key_raises(self, key, plaintext):
        """Decrypting with a different key fails due to wrong derived key."""
        engine = CryptoEngine(key)
        ct = engine.encrypt_data(plaintext)
        with pytest.raises(Exception):
            CryptoEngine.decrypt_payload("completely_wrong_key", ct)

    def test_ciphertext_uniqueness(self, key, plaintext):
        """
        Two encryptions of the same plaintext produce different ciphertexts
        (due to random salt and nonce per encryption).
        """
        e1 = CryptoEngine(key)
        e2 = CryptoEngine(key)
        assert e1.encrypt_data(plaintext) != e2.encrypt_data(plaintext)
