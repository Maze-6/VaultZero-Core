# 🧊 VaultZero: Distributed Defense Grid

**Lead Architect & Cryptographic Engineer:** Mourya Reddy Udumula
**SecOps Lead:** Jeet Anand Upadhyaya
**Presented at:** Indrashil University Research Symposium, January 2026 *(reviewed by ISRO scientists)*

---

## 🧠 What Is VaultZero?

VaultZero is a fault-tolerant distributed storage grid engineered to eliminate Single Points of Failure (SPOF) using threshold cryptography. No single node holds a complete file or its decryption key. The system tolerates node failures, detects intrusions via an active honeypot layer, and recovers data from any 2-of-3 nodes.

The original implementation crashed 37% of the time under 1,000 concurrent requests due to race conditions in async shard writes. This restructured version resolves those failures, adds a full test suite, CI/CD, and verifies performance at production load.

---

## 📊 Verified Performance (1,000-op Benchmark)

| Method | Throughput | Error Rate | Total Time |
|--------|-----------|------------|------------|
| AsyncIO encrypt/decrypt | 106 ops/s | 0.0% | 9,393 ms |
| AsyncIO Shamir split/recon | 1,553 ops/s | 0.0% | 644 ms |
| Threading encrypt/decrypt | 101 ops/s | 0.0% | 9,911 ms |
| Threading Shamir split/recon | 1,215 ops/s | 0.0% | 822 ms |

- **85% crash reduction** (37% → <5% error rate) under 1,000 concurrent requests.
- **35% throughput improvement** from pre-AsyncIO sequential baseline (2,300 → 3,100 ops/sec).

Run the full benchmark yourself:

```bash
python tests/test_load.py --full
```

---

## 🏗️ Architecture

```
Client ──► Gateway ──► Crypto Engine (AES-256-GCM + PBKDF2)
                               │
               ┌───────────────┼───────────────┐
               ▼               ▼               ▼
          Node Alpha       Node Beta       Node Gamma
        data_storage/    data_storage/   data_storage/
         key_storage/     key_storage/    key_storage/
        [Data Shard 0]   [Data Shard 1]  [Data Shard 2]
        [Key Shard 0]    [Key Shard 1]   [Key Shard 2]
```

**Zero-trust design:** Data shards and key shards are stored in physically separate directories, mimicking isolated Hardware Security Modules (HSMs). No node can decrypt data without combining key shards from at least 2 other nodes.

**Threshold recovery:** Uses Shamir's Secret Sharing (k=2, n=3) — any 2 of 3 nodes are sufficient to reconstruct the key and decrypt the file. One node can go offline without data loss.

---

## 🔐 Cryptographic Stack

| Layer | Implementation | Detail |
|-------|---------------|--------|
| Symmetric Encryption | AES-256-GCM | Authenticated encryption — detects tampering |
| Key Derivation | PBKDF2-HMAC-SHA256 | 100,000 iterations, per-encryption random salt |
| Key Splitting | Shamir's Secret Sharing | 2-of-3 threshold scheme |
| Shard Transport | AsyncIO + aiofiles | Non-blocking concurrent writes |
| Integrity Monitoring | SHA-256 honeypot hash | Active breach detection on Node Alpha |

---

## 🛡️ Active Defense Layer

VaultZero includes an intrusion detection system built around a honeypot file (`data_storage/node1/admin_credentials.txt`) containing realistic fake credentials. On every session start:

1. The file's SHA-256 hash is computed and compared against a stored golden hash
2. Any modification — even a single character — triggers a 🚨 `BREACH_DETECTED` audit event
3. Node Alpha's status changes to `COMPROMISED` in the dashboard
4. A red alert banner appears and the sidebar shows the restoration button

All security events are written to a tamper-evident forensic audit log with UTC and IST timestamps.

---

## 📂 Engineering Attribution

| Module | Lead | Core Technology |
|--------|------|----------------|
| `crypto_engine.py` | Mourya Udumula | AES-256-GCM, PBKDF2-HMAC-SHA256 |
| `shamir_handler.py` | Mourya Udumula | Shamir Secret Sharing, AsyncIO shard distribution |
| `db_handler.py` | Mourya Udumula | SQLite file registry (add/remove/list) |
| `main.py` | Mourya Udumula | Streamlit orchestrator, session auth, audit logging |
| `config.py` | Mourya Udumula | Node topology, path config, honeypot credentials |
| `tests/` (57 tests) | Mourya Udumula | pytest suite: crypto, Shamir, load, watchdog |
| `ops/watchdog_service.py` | Jeet Upadhyaya | Filesystem watchdog, breach detection daemon |
| `ops/audit_ledger.py` | Jeet Upadhyaya | Forensic log management |

---

## ✅ Test Suite (57 Tests)

```bash
python -m pytest tests/ -v
```

Tests cover:

- `test_crypto.py` — AES-GCM encrypt/decrypt roundtrip, tamper detection, salt uniqueness, PBKDF2 key derivation
- `test_shamir.py` — 2/3 quorum recovery, 3/3 recovery, single-node failure, padding/unpadding correctness
- `test_load.py` — Concurrent AsyncIO and threading benchmarks at 20-op (CI) and 1,000-op (full) scales
- `test_watchdog.py` — Honeypot hash verification, breach detection, restoration

CI runs on every push and pull request via GitHub Actions (`.github/workflows/tests.yml`).

---

## 🔧 Installation & Quickstart

```bash
# Clone
git clone https://github.com/Maze-6/VaultZero-Core.git
cd VaultZero-Core

# Install dependencies
pip install -r requirements.txt

# Run tests
python -m pytest tests/ -v

# Verify the full crypto pipeline
python roundtrip_test.py

# Run the production load benchmark
python tests/test_load.py --full

# Launch the dashboard
streamlit run main.py
```

---

## 📦 Requirements

```
streamlit
pycryptodome
aiofiles
plotly
watchdog
pandas
graphviz
```

---

## 📁 Repository Structure

```
VaultZero-Core/
├── main.py                  # Streamlit dashboard + orchestration
├── crypto_engine.py         # AES-256-GCM + PBKDF2 implementation
├── shamir_handler.py        # Threshold cryptography (2-of-3)
├── db_handler.py            # SQLite file registry
├── config.py                # Node topology, paths, honeypot config
├── roundtrip_test.py        # End-to-end crypto verification script
├── requirements.txt
├── .github/
│   └── workflows/tests.yml  # CI/CD pipeline
├── tests/
│   ├── test_crypto.py
│   ├── test_shamir.py
│   ├── test_load.py         # Supports --full flag for 1,000-op benchmark
│   └── test_watchdog.py
├── ops/
│   ├── watchdog_service.py  # Filesystem breach detection daemon
│   └── audit_ledger.py      # Forensic log management
├── data_storage/            # [gitignored] Encrypted data shards
├── key_storage/             # [gitignored] Shamir key shards
└── registry.db              # [gitignored] SQLite file registry
```

---

## 🔬 Key Engineering Decisions

### Why AsyncIO over threading for shard writes?

Shard writes are I/O-bound, not CPU-bound. AsyncIO's event loop eliminates the thread contention that caused the original 37% crash rate — threads were racing to write to the same node directories simultaneously. AsyncIO serializes I/O scheduling while keeping writes non-blocking, eliminating the race condition entirely.

### Why Shamir over symmetric key replication?

Replicating the same key to all nodes means any single compromised node leaks the entire key. Shamir's Secret Sharing means a stolen shard is cryptographically useless — an attacker needs at least 2 shards to reconstruct anything.

### Why per-encryption random salt in PBKDF2?

Using a fixed salt means two encryptions with the same password produce the same derived key — allowing ciphertext comparison attacks. Random salt per encryption ensures identical passwords produce different keys every time.

---

*Senior capstone research — Indrashil University*
[mouryaudumula@gmail.com](mailto:mouryaudumula@gmail.com)
