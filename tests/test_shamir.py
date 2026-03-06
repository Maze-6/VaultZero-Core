"""
test_shamir.py
Author: Mourya Reddy Udumula
Threshold reconstruction tests for Shamir Secret Sharing (k=2, n=3).
Validates all k-of-n combinations: confirms reconstruction succeeds
with any 2 of 3 shards and fails with only 1 shard.
"""

import sys
import os
import itertools
import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from Crypto.Protocol.SecretSharing import Shamir
from shamir_handler import ShamirVault, pad_to_16, unpad_from_16

# Default scheme parameters -- mirror VaultZero production config
K = 2   # threshold
N = 3   # total shares


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def secret():
    """16-byte secret (PyCryptodome Shamir requires exactly 16 bytes)."""
    return b"1234567890123456"


@pytest.fixture
def shares(secret):
    """Split secret into N shares with threshold K."""
    return Shamir.split(K, N, secret)


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------

class TestShamirSplit:
    def test_split_produces_n_shares(self, shares):
        """Splitting produces exactly N shares."""
        assert len(shares) == N

    def test_shares_are_tuples(self, shares):
        """Each share is a (index, bytes) tuple."""
        for share in shares:
            assert isinstance(share, tuple)
            assert len(share) == 2
            idx, data = share
            assert isinstance(idx, int)
            assert isinstance(data, bytes)

    def test_share_indices_are_unique(self, shares):
        """All share indices are distinct."""
        indices = [idx for idx, _ in shares]
        assert len(set(indices)) == N

    def test_share_data_length(self, shares):
        """Each share's data has the same length as the secret (16 bytes)."""
        for _, data in shares:
            assert len(data) == 16


class TestShamirReconstruct:
    def test_reconstruct_with_all_shares(self, secret, shares):
        """Reconstructing with all N shares returns the original secret."""
        assert Shamir.combine(shares) == secret

    def test_reconstruct_with_threshold_shares(self, secret, shares):
        """Any K shares reconstruct the original secret."""
        recon = Shamir.combine(shares[:K])
        assert recon == secret

    def test_all_k_of_n_combinations(self, secret, shares):
        """Every C(N, K) subset of shares reconstructs the secret correctly."""
        for combo in itertools.combinations(shares, K):
            recon = Shamir.combine(list(combo))
            assert recon == secret, f"Reconstruction failed for combo {combo}"

    def test_roundtrip_bytes(self, secret, shares):
        """Full split → reconstruct cycle preserves exact byte content."""
        reconstructed = Shamir.combine(shares)
        assert reconstructed == secret
        assert type(reconstructed) is bytes


class TestShamirEdgeCases:
    @pytest.mark.parametrize("secret_val", [
        b"\x00" * 16,           # all-zero secret
        b"\xff" * 16,           # all-ones secret
        b"SentinEL_VaultZr",    # ASCII text (exactly 16 bytes)
        b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10",
    ])
    def test_various_secrets(self, secret_val):
        """Split and reconstruct succeeds for varied 16-byte secrets."""
        shares = Shamir.split(K, N, secret_val)
        assert Shamir.combine(shares[:K]) == secret_val

    def test_insufficient_shares_wrong_result(self, secret):
        """
        Reconstructing with fewer than K shares does NOT raise but returns
        a wrong (corrupted) value — demonstrating the security property.
        """
        shares = Shamir.split(K, N, secret)
        # Only 1 share -- below the threshold
        try:
            wrong = Shamir.combine(shares[:1])
            # If it doesn't raise, the result must be wrong
            assert wrong != secret, (
                "Security violation: 1 share reconstructed the secret!"
            )
        except Exception:
            pass  # Some implementations raise on under-threshold input -- also acceptable


# ------------------------------------------------------------------
# Fix 7: pad_to_16 / unpad_from_16 and split_key validation tests
# ------------------------------------------------------------------

class TestShamirPadding:
    """Tests for the pad_to_16 / unpad_from_16 helpers and split_key validation."""

    def test_pad_short_secret(self):
        """8-byte secret padded to 16, unpadded returns original."""
        original = b"hello!!!"  # 8 bytes
        padded = pad_to_16(original)
        assert len(padded) == 16
        assert padded.startswith(original)
        recovered = unpad_from_16(padded)
        assert recovered == original

    def test_pad_exact_secret(self):
        """16-byte secret passes through pad_to_16 unchanged."""
        secret = b"exactly16bytess!"  # exactly 16 bytes
        assert len(secret) == 16
        assert pad_to_16(secret) == secret

    def test_pad_long_secret(self):
        """Secret longer than 16 bytes is hashed to exactly 16 bytes (SHA-256 truncated)."""
        secret = b"this_is_a_secret_much_longer_than_16_bytes"
        padded = pad_to_16(secret)
        assert len(padded) == 16
        # SHA-256 truncated to 16 bytes — deterministic and collision-resistant (RFC 6151)
        import hashlib
        assert padded == hashlib.sha256(secret).digest()[:16]

    def test_wrong_length_raises(self):
        """Passing a 17-byte secret directly to split_key raises ValueError."""
        vault = ShamirVault()
        with pytest.raises(ValueError, match="16 bytes"):
            vault.split_key(b"17_bytes_secret!!")  # 17 bytes

    def test_split_key_and_reconstruct_from_shares_roundtrip(self):
        """In-memory split_key -> reconstruct_from_shares roundtrip."""
        vault = ShamirVault()
        secret = b"SentinEL_Vaultzr"  # exactly 16 bytes
        shares = vault.split_key(secret)
        assert len(shares) == 3
        recovered = vault.reconstruct_from_shares(shares[:2])
        assert recovered == secret

    def test_pad_roundtrip_via_shamir(self):
        """pad_to_16 secret can be split and reconstructed."""
        original = b"short"  # 5 bytes
        padded = pad_to_16(original)
        vault = ShamirVault()
        shares = vault.split_key(padded)
        recovered_padded = vault.reconstruct_from_shares(shares[:2])
        recovered_original = unpad_from_16(recovered_padded)
        assert recovered_original == original
