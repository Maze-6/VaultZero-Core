import time
import os
import hashlib
import config
from datetime import datetime, timezone

# Tracker for the last version of the breach we alerted about
last_alerted_hash = None

def get_file_hash(filepath):
    if not os.path.exists(filepath): return None
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
            clean_content = "".join(content.split())
            return hashlib.sha256(clean_content.encode('utf-8')).hexdigest()
    except: return None

def log_event(event_type, message):
    utc_now = datetime.now(timezone.utc)
    ist_now = datetime.now()
    entry = f"{utc_now.strftime('%Y-%m-%d %H:%M:%S')}|{ist_now.strftime('%Y-%m-%d %H:%M:%S')}|WATCHDOG|{event_type}|{message}|[USER: External/System]\n"
    with open(config.AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(entry)
        f.flush()

def start_watchdog():
    global last_alerted_hash
    target = config.HONEYPOT_FILE
    
    if not os.path.exists(target):
        with open(target, "w", encoding="utf-8") as f: f.write(config.BAIT_CONTENT)
    
    print(f"[JEET] WATCHDOG ACTIVE - MONITORING NODE ALPHA...")
    
    while True:
        try:
            curr_hash = get_file_hash(target)
            
            if curr_hash != config.GOLDEN_HASH:
                if curr_hash != last_alerted_hash:
                    ts = datetime.now().strftime("%H:%M:%S")
                    print(f"!!! NEW BREACH DETECTED AT {ts} !!!")
                    
                    with open(config.SECURITY_LOG, "a", encoding="utf-8") as f:
                        f.write(f"{ts} | CRITICAL | INTEGRITY FAIL | Hash: {curr_hash[:8]}...\n")
                    
                    log_event("🔴 CRITICAL", "Integrity Check Failed (File Modified)")
                    last_alerted_hash = curr_hash 
            
            elif curr_hash == config.GOLDEN_HASH and last_alerted_hash is not None:
                print(f"[RECOVERY] SYSTEM SECURED AT {datetime.now().strftime('%H:%M:%S')}")
                last_alerted_hash = None 
                
        except Exception as e:
            print(f"Error: {e}")
        
        time.sleep(1)

if __name__ == "__main__":
    start_watchdog()