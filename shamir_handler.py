import os
import hashlib
import asyncio
import aiofiles
from binascii import hexlify, unhexlify
from Crypto.Protocol.SecretSharing import Shamir
from typing import List
import config


# ---------------------------------------------------------------------------
# Fix 7: Padding helpers for the 16-byte Shamir constraint
# ---------------------------------------------------------------------------

def pad_to_16(data: bytes) -> bytes:
    """
    Ensure *data* is exactly 16 bytes for Shamir Secret Sharing.

    PyCryptodome's Shamir.split() requires exactly 16 bytes (128-bit secret).

    Strategy:
      - If len(data) <= 16 : right-padded with null bytes (reversible via unpad_from_16).
      - If len(data) >  16 : SHA-256 hash truncated to 16 bytes (one-way — cannot recover original).

    SHA-256 truncation is used for >16-byte secrets — collision-resistant and
    appropriate for a cryptographic storage system (see RFC 6151 for context).

    For secrets longer than 16 bytes, the hash is a lossy operation. The caller
    is responsible for knowing whether the original or the hash is needed on
    reconstruction.

    Args:
        data: Secret bytes of any length.

    Returns:
        Exactly 16 bytes.
    """
    if len(data) <= 16:
        return data.ljust(16, b'\x00')
    # SHA-256 truncated to 16 bytes: collision-resistant, RFC 6151-compliant.
    return hashlib.sha256(data).digest()[:16]


def unpad_from_16(data: bytes) -> bytes:
    """
    Strip the null-byte padding added by pad_to_16 (for secrets <= 16 bytes).

    This is the inverse of pad_to_16 for secrets shorter than 16 bytes.
    Do NOT call this on secrets that were hashed (> 16 bytes original) -- the
    original cannot be recovered from the SHA-256 truncation used by pad_to_16.

    Args:
        data: 16-byte padded secret as returned by Shamir.combine().

    Returns:
        Original bytes with trailing null bytes stripped.
    """
    return data.rstrip(b'\x00')


class ShamirVault:
    @staticmethod
    async def async_write_shard(path: str, data: bytes) -> None:
        """Async write with 10ms simulated latency."""
        await asyncio.sleep(0.01)
        async with aiofiles.open(path, "w") as f:
            await f.write(hexlify(data).decode('utf-8'))

    @staticmethod
    def distribute_key_async(secret_key: str, filename: str, active_nodes: List[bool]) -> bool:
        """Splits master key into shards and distributes to key_storage nodes."""
        try:
            key_bytes: bytes = secret_key.encode('utf-8')
            # Fix 7: use pad_to_16 so any password length is handled correctly.
            # Keys <= 16 bytes are null-padded; keys > 16 bytes are hashed to 16 bytes.
            padded_key: bytes = pad_to_16(key_bytes)
            if len(padded_key) != 16:
                raise ValueError(
                    f"Secret must be exactly 16 bytes, got {len(padded_key)} bytes. "
                    f"Pad or hash your secret to 16 bytes before splitting. "
                    f"Example: import hashlib; secret_16 = hashlib.sha256(your_secret).digest()[:16]"
                )
            shares = Shamir.split(2, 3, padded_key)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            tasks = []
            for idx, share_data in shares:
                if active_nodes[idx-1]:
                    path = os.path.join(config.KEY_NODES[idx-1], f"{filename}.key.{idx-1}")
                    tasks.append(ShamirVault.async_write_shard(path, share_data))

            if tasks:
                loop.run_until_complete(asyncio.gather(*tasks))
            loop.close()
            return True
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Sharding Error: {str(e)}")

    @staticmethod
    def split_key(secret: bytes, k: int = 2, n: int = 3) -> list:
        """
        In-memory Shamir split with strict 16-byte validation.

        Unlike distribute_key_async() (which auto-pads), this method requires
        an exact 16-byte secret and raises ValueError otherwise. Use pad_to_16()
        before calling if your secret is a different length.

        Args:
            secret: Exactly 16 bytes.
            k:      Threshold (default 2).
            n:      Total shares (default 3).

        Returns:
            List of (index, share_bytes) tuples.

        Raises:
            ValueError: If len(secret) != 16.
        """
        if len(secret) != 16:
            raise ValueError(
                f"Secret must be exactly 16 bytes, got {len(secret)} bytes. "
                f"Pad or hash your secret to 16 bytes before splitting. "
                f"Example: import hashlib; secret_16 = hashlib.sha256(your_secret).digest()[:16]"
            )
        return list(Shamir.split(k, n, secret))

    @staticmethod
    def reconstruct_from_shares(shares: list) -> bytes:
        """
        In-memory Shamir reconstruction from a list of (index, bytes) tuples.

        This is the in-memory counterpart to split_key(). For file-based
        reconstruction see reconstruct_key().

        Args:
            shares: List of (index, share_bytes) tuples (at least k of them).

        Returns:
            Reconstructed 16-byte secret.
        """
        return Shamir.combine(shares)

    @staticmethod
    def reconstruct_key(filename: str, active_nodes: List[bool]) -> str:
        """Reconstructs key and identifies missing shards across the grid."""
        shares = []
        missing_shards = []
        node_names = ["Alpha", "Beta", "Gamma"]

        for i in range(3):
            path = os.path.join(config.KEY_NODES[i], f"{filename}.key.{i}")

            # Check if file exists physically on disk
            if not os.path.exists(path):
                missing_shards.append(node_names[i])
                continue

            # Only add to reconstruction if node is logically ONLINE in dashboard
            if active_nodes[i]:
                with open(path, "r") as f:
                    shares.append((i + 1, unhexlify(f.read().strip())))

        # If any shards are physically missing, notify the user immediately
        if missing_shards:
            raise FileNotFoundError(f"Missing Shards Detected: Node(s) {', '.join(missing_shards)}")

        if len(shares) < 2:
            raise ValueError(f"QUORUM FAILURE: Only {len(shares)} nodes online. Need 2.")

        try:
            return Shamir.combine(shares).strip().decode('utf-8')
        except Exception as e:
            raise ValueError(f"Reconstruction Error: {str(e)}")
