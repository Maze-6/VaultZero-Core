"""
VaultZero — Step 6 Roundtrip Verification
Run from VaultZero-Restructured directory with venv active:
    python roundtrip_test.py
"""

import os
import config
from crypto_engine import CryptoEngine
from shamir_handler import ShamirVault

print("=" * 50)
print("  VaultZero Roundtrip Test")
print("=" * 50)

# ── Setup: make sure node directories exist ────────────────
for path in list(config.DATA_NODES.values()) + list(config.KEY_NODES.values()):
    os.makedirs(path, exist_ok=True)

ALL_NODES_ONLINE = [True, True, True]
TWO_NODES_ONLINE = [True, True, False]   # Node Gamma offline
TEST_FILENAME    = "__roundtrip_test__"
password         = "mypassword123"
plaintext        = b"VaultZero integration test - sensitive data payload"

# ── Step 1: Encrypt ────────────────────────────────────────
engine = CryptoEngine(password)
ciphertext = engine.encrypt_data(plaintext)
print(f"[1] Encrypted successfully  —  ciphertext length: {len(ciphertext)} bytes")

# ── Step 2: Distribute key shards to disk (all 3 nodes) ───
ShamirVault.distribute_key_async(password, TEST_FILENAME, ALL_NODES_ONLINE)
print(f"[2] Key shards distributed  —  written to all 3 nodes")

# ── Step 3: Reconstruct from all 3 nodes ──────────────────
recovered_raw = ShamirVault.reconstruct_key(TEST_FILENAME, ALL_NODES_ONLINE)
recovered = recovered_raw.rstrip('\x00')   # strip Shamir null-byte padding
print(f"[3] Reconstructed (3/3)     —  password match: {recovered == password}")

# ── Step 4: Reconstruct from only 2 nodes (threshold test) ─
recovered_raw_2 = ShamirVault.reconstruct_key(TEST_FILENAME, TWO_NODES_ONLINE)
recovered_2 = recovered_raw_2.rstrip('\x00')
print(f"[4] Reconstructed (2/3)     —  password match: {recovered_2 == password}")

# ── Step 5: Decrypt and verify original plaintext ─────────
# decrypt_payload is a static method: CryptoEngine.decrypt_payload(password, ciphertext)
decrypted = CryptoEngine.decrypt_payload(recovered_2, ciphertext)
print(f"[5] Full roundtrip success  —  plaintext match: {decrypted == plaintext}")

# ── Cleanup: remove test shards from disk ─────────────────
for i in range(3):
    key_p = os.path.join(list(config.KEY_NODES.values())[i], f"{TEST_FILENAME}.key.{i}")
    if os.path.exists(key_p): os.remove(key_p)
print(f"[6] Test shards cleaned up  —  no leftover files")

# ── Final verdict ──────────────────────────────────────────
print()
if recovered == password and recovered_2 == password and decrypted == plaintext:
    print("  ALL CHECKS PASSED — crypto pipeline is working correctly")
else:
    print("  ONE OR MORE CHECKS FAILED — see output above")
print("=" * 50)
