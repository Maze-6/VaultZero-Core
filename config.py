import os
import hashlib

# INFRASTRUCTURE: Logical separation of data and keys
DATA_NODES = {
    0: "data_storage/node1",
    1: "data_storage/node2",
    2: "data_storage/node3"
}

KEY_NODES = {
    0: "key_storage/node1",
    1: "key_storage/node2",
    2: "key_storage/node3"
}

# SQLite DB for ACID compliance
DB_PATH = "registry.db"

# AUTO-SETUP
for paths in [DATA_NODES.values(), KEY_NODES.values()]:
    for path in paths:
        if not os.path.exists(path):
            os.makedirs(path)

# LOGS
LATENCY_LOG = "performance_metrics.json"
SECURITY_LOG = "security_events.log"
AUDIT_LOG = "audit_trail.log"

# HONEYPOT LOCATION
HONEYPOT_FILE = os.path.join(DATA_NODES[0], "admin_credentials.txt") 

# --- HONEYPOT CONTENT (THE GOLDEN IMAGE) ---
# This is the "Truth". If the file on disk differs from this string, 
# the system triggers an alert.
BAIT_CONTENT = """# ADMIN CREDENTIALS - DO NOT SHARE
username: admin1
password:admin@123"""

# Calculate baseline hash automatically based on the content above
GOLDEN_HASH = hashlib.sha256(BAIT_CONTENT.encode()).hexdigest()