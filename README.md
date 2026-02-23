# VaultZero

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker&logoColor=white)
![Crypto](https://img.shields.io/badge/Crypto-AES--256--GCM%20%7C%20Shamir%20SSS-DC143C?style=flat-square)
![Research](https://img.shields.io/badge/Type-Capstone%20Research-4B0082?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-22C55E?style=flat-square)

**Eliminating single points of failure in distributed key-value storage through threshold cryptography and AsyncIO orchestration.**

</div>

---

## Results at a Glance

| Metric | Baseline | VaultZero | Improvement |
|--------|----------|-----------|-------------|
| Crash rate (1,000 concurrent requests) | 37% | **< 5%** | **85% reduction** |
| Write throughput | 2,300 ops/sec | **3,100 ops/sec** | **+35%** |
| Single points of failure | Multiple | **0** | **Full elimination** |
| Secret reconstruction | N/A | **k=2 of n=3 shards** | Threshold scheme |

The throughput improvement was not a separate optimisation — it is a side effect of removing lock contention during the AsyncIO refactor.

---

## Table of Contents

- [Why This Matters](#why-this-matters)
- [The Problem](#the-problem)
- [Architecture](#architecture)
- [Cryptographic Design](#cryptographic-design)
- [Root Cause Analysis — What Actually Fixed the Crashes](#root-cause-analysis)
- [Repository Structure](#repository-structure)
- [Getting Started](#getting-started)
- [Limitations & Future Work](#limitations--future-work)
- [Presentation](#presentation)
- [Citation](#citation)

---

## Why This Matters

Most distributed storage implementations treat the key manager as a single trusted component. Under concurrent load — or under adversarial targeting — this creates two simultaneous failure modes:

- **A crashed key-manager node takes the entire system offline.** There is no redundancy at the cryptographic layer.
- **A compromised key-manager node exposes everything.** Encrypting data at rest is meaningless if a single breach yields the key.

VaultZero treats these as two facets of the same architectural mistake: centralised trust. Distributing key material across shards using Shamir's Secret Sharing eliminates both failure modes simultaneously — without sacrificing throughput.

---

## The Problem

Standard distributed storage systems concentrate cryptographic keys in a single location. Under concurrent load or targeted attack, this creates two failure modes:

1. **Availability failure:** A crashed key-manager node takes the entire system offline.
2. **Security failure:** Compromising a single node exposes all stored secrets.

VaultZero addresses both by distributing key material using Shamir's Secret Sharing and eliminating lock contention through AsyncIO-based shard orchestration.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    CLIENT LAYER                      │
│              (concurrent request pool)               │
└────────────────────┬────────────────────────────────┘
                     │  HTTPS
                     ▼
┌─────────────────────────────────────────────────────┐
│               ORCHESTRATION LAYER                    │
│           main.py  ·  AsyncIO event loop             │
│    • Request routing                                 │
│    • Shard coordination                              │
│    • Error recovery                                  │
└──────────┬──────────────┬──────────────┬────────────┘
           │              │              │
           ▼              ▼              ▼
┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   SHARD 0    │  │   SHARD 1    │  │   SHARD 2    │
│  (replica)   │  │  (replica)   │  │  (replica)   │
└──────────────┘  └──────────────┘  └──────────────┘
         │                │                │
         └────────────────┼────────────────┘
                          │ k=2 of n=3 required for reconstruction
                          ▼
┌─────────────────────────────────────────────────────┐
│              CRYPTOGRAPHIC LAYER                     │
│  shamir_handler.py  ·  crypto_engine.py             │
│  • Shamir's Secret Sharing (k=2, n=3)               │
│  • AES-256-GCM authenticated encryption             │
│  • PBKDF2 key derivation (100,000 iterations)       │
└─────────────────────────────────────────────────────┘
```

**System behaviour under node failure:** With k=2 of n=3, the system remains fully operational with any single shard down. Two simultaneous shard failures are required to cause unavailability. A single compromised shard yields no usable key material — an attacker must control at least 2 of 3 shards simultaneously.

---

## Cryptographic Design

### Shamir's Secret Sharing (k=2, n=3)

An encryption key is split into **3 shares** distributed across 3 shard nodes. Any **2 shares** reconstruct the original key. A single compromised node reveals nothing useful.

This provides:
- **Availability:** System remains operational with any 2/3 shards alive
- **Confidentiality:** Single-node compromise yields no usable secret material

### AES-256-GCM

All stored data is encrypted using AES-256-GCM (authenticated encryption with associated data). GCM mode provides both confidentiality *and* integrity verification — a tampered ciphertext is detected on decryption rather than silently decrypted to garbage. This is important in distributed environments where individual shard storage may be less trusted than centralised storage.

### PBKDF2 (100,000 iterations)

User passphrases are never used directly as encryption keys. PBKDF2 with 100,000 iterations stretches passphrases into cryptographic keys while adding brute-force resistance. The iteration count follows NIST SP 800-132 recommendations.

---

## Root Cause Analysis

The 85% crash reduction was not achieved by simply switching to AsyncIO. It required understanding why the crashes occurred.

**Step 1 — Profile under load.** Crashes clustered around concurrent shard write operations, not reads. This narrowed the problem to the write path.

**Step 2 — Identify the race condition.** The threading implementation maintained a shared `active_shards` dict that multiple threads could modify simultaneously without proper locking, producing inconsistent state under concurrent load.

**Step 3 — Evaluate solutions.** Two options were compared:

| Approach | Crash Rate | Throughput | Verdict |
|---|---|---|---|
| `threading.Lock()` | ~18% | Bottlenecked (lock contention) | Partial improvement; introduces new ceiling |
| AsyncIO cooperative multitasking | **< 5%** | **+35% vs baseline** | Eliminates shared-state problem entirely |

`threading.Lock()` reduced crashes but introduced a throughput bottleneck — threads waiting to acquire the lock serialised what should be concurrent operations. AsyncIO's cooperative multitasking eliminated the shared-state problem at the design level: only one coroutine runs at a time within the event loop, so the `active_shards` dict is never accessed concurrently.

**The throughput improvement is a side effect of removing the lock, not a separate optimisation.**

---

## Repository Structure

```
vaultzero/
├── crypto_engine.py      # AES-256-GCM implementation, PBKDF2 key derivation
├── shamir_handler.py     # Threshold secret sharing (split + reconstruct)
├── main.py               # AsyncIO orchestration layer, request routing
├── shard_manager.py      # Shard lifecycle management, health monitoring
├── tests/
│   ├── test_crypto.py    # Unit tests for encryption/decryption correctness
│   ├── test_shamir.py    # Threshold reconstruction tests (all k-of-n combos)
│   └── test_load.py      # Concurrent load tests (generates the results above)
├── docs/
│   └── VaultZero_Technical_Report.pdf
├── docker-compose.yml    # Multi-shard deployment (3 containers)
└── requirements.txt
```

---

## Getting Started

**Prerequisites:** Python 3.10+, Docker, Docker Compose

```bash
# Clone and start the shard cluster
git clone https://github.com/Maze-6/VaultZero-Core
cd VaultZero-Core
docker-compose up -d

# Store a secret
python main.py store --key "my-secret-id" --value "sensitive-data"

# Retrieve a secret (requires k=2 shards responding)
python main.py retrieve --key "my-secret-id"

# Run load tests (reproduces the results table above)
python tests/test_load.py --concurrency 1000 --iterations 500
```

> **Note on benchmark environment:** All performance figures were measured on a MacBook Pro M2 (16GB RAM) with shards running in Docker containers on the same host. Production deployment on separate physical nodes would show different fault isolation characteristics — likely better, as co-located containers share underlying hardware failure domains.

---

## Limitations & Future Work

| Limitation | Detail |
|---|---|
| **Shard placement** | Currently assumes shards on separate hosts. Co-located deployment reduces availability guarantees by sharing failure domains. |
| **Network partitions** | Non-responding shards are treated as failed. Split-brain scenarios under network partition are not handled — this is the most significant production limitation. |
| **Key rotation** | Rotating encryption keys requires a full re-encryption pass. Online key rotation without service interruption is not implemented. |
| **Formal security proof** | The threat model is described informally. A formal proof under the UC framework is future work. |

---

## Presentation

Presented at the **Indrashil University Research Symposium** (January 2026), with an audience that included scientists from the **Indian Space Research Organisation (ISRO)**.

Full design rationale, security analysis, and experimental methodology: [`docs/VaultZero_Technical_Report.pdf`](docs/VaultZero_Technical_Report.pdf)

---

## Citation

```
Udumula, Mourya Reddy. "VaultZero: Fault-Tolerant Distributed Storage via 
Threshold Cryptography and AsyncIO Orchestration." Senior Capstone Research, 
Indrashil University, 2025–2026.
```

---

<div align="center">

*Senior capstone research — Indrashil University*  
[mouryaudumula@gmail.com](mailto:mouryaudumula@gmail.com)

</div>
