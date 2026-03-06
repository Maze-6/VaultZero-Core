# Contributors

## VaultZero — Fault-Tolerant Distributed Storage System
*Indrashil University Capstone Project | September 2025 – January 2026*
*Presented at Indrashil University Annual Research Symposium 2025*

### Mourya Reddy Udumula — Lead Architect & Cryptographic Engineer
- AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 (100k iterations)
- Shamir's Secret Sharing threshold cryptography (k=2, n=3)
- AsyncIO orchestration: 85% crash reduction, 35% throughput improvement
- Zero-trust shard architecture (data shards and key shards physically separated)
- Files: `crypto_engine.py`, `shamir_handler.py`, `main.py`, `shard_manager.py`, `tests/`

### Jeet Upadhyaya Anand — SecOps Lead & Forensic Engineer
- Forensic Audit Ledger: SQLite ACID-compliant dual-timestamp logging (UTC + IST)
- Digital Minefields: Python Watchdog honeypot agents with real-time node isolation
- Chain-of-custody compliant evidence logging
- Operational monitoring: < 3% CPU overhead under full load
- Files: `ops/audit_ledger.py`, `ops/watchdog_service.py`

---
*Contact: mouryaudumula@gmail.com | jeetupadhyaya14@gmail.com*
