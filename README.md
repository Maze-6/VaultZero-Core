# 🧊 VaultZero: Distributed Defense Grid

### Fault-Tolerant Decentralized Storage with Active Defense Protocols
**Architects:** Mourya R. Udumula & Jeet Upadhyaya | **Institution:** Indrashil University

---

## 🚀 Project Overview
VaultZero is a next-generation storage infrastructure designed to eliminate single points of failure. It utilizes **Shamir’s Secret Sharing (k=2, n=3)** to mathematically fracture data and keys across logically separated nodes, ensuring that no single compromised node yields usable data.

Unlike passive storage systems, VaultZero features an **Active Defense Watchdog** that monitors integrity in real-time, triggering automated lockdowns upon detecting unauthorized access patterns.

## 🛠️ Technical Stack
*   **Core Logic:** Python 3.9, AsyncIO (Concurrency)
*   **Cryptography:** AES-256-GCM (Authenticated Encryption), PBKDF2 (Key Stretching)
*   **Distribution:** Shamir's Secret Sharing (Information Theoretic Security)
*   **Persistence:** SQLite (ACID Compliance)
*   **Ops:** Automated Forensics & Self-Healing Infrastructure

## ⚡ Key Features
1.  **Trustless Architecture:** Data and Keys are stored in separate logical partitions (`data_storage` vs `key_storage`).
2.  **Self-Healing Infrastructure:** Automated regeneration of critical configuration files and honeypots on boot.
3.  **Active Defense:** Integrated Honeypot (`admin_credentials.txt`) triggers immediate system lockdown if modified.
4.  **Forensic Audit Trail:** Immutable logging of all access events with UTC/IST timestamps.

## 🔧 Installation & Usage
```bash
# Clone the repository
git clone https://github.com/Maze-6/VaultZero-Core.git

# Install dependencies
pip install -r requirements.txt

# Launch the Grid
streamlit run main.py
