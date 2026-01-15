import os
import hashlib

# INFRASTRUCTURE SETTINGS
DATA_NODES = {0: "data_storage/node1", 1: "data_storage/node2", 2: "data_storage/node3"}
KEY_NODES = {0: "key_storage/node1", 1: "key_storage/node2", 2: "key_storage/node3"}
DB_PATH = "registry.db"

# AUTO-SETUP
for paths in [DATA_NODES.values(), KEY_NODES.values()]:
    for path in paths:
        if not os.path.exists(path): os.makedirs(path)

# LOGGING ARCHIVE
LATENCY_LOG = "performance_metrics.json"
SECURITY_LOG = "security_events.log"
AUDIT_LOG = "audit_trail.log"
HONEYPOT_FILE = os.path.join(DATA_NODES[0], "admin_credentials.txt") 

# SYSTEM CREDENTIALS (THE GOLDEN IMAGE)
BAIT_CONTENT = """# ADMIN CREDENTIALS - DO NOT SHARE
username: admin1
password:admin@123"""

def get_gold_hash(text):
    # Forensic Normalization: Strip whitespace to prevent fake breaches
    return hashlib.sha256("".join(text.split()).encode('utf-8')).hexdigest()

GOLDEN_HASH = get_gold_hash(BAIT_CONTENT)