import time
import os
import hashlib
import config
from datetime import datetime, timedelta

def get_file_hash(filepath):
    if not os.path.exists(filepath): return None
    with open(filepath, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()

def log_event(event_type, message):
    utc_now = datetime.utcnow()
    ist_now = utc_now + timedelta(hours=5, minutes=30)
    
    t_utc = utc_now.strftime("%Y-%m-%d %H:%M:%S")
    t_ist = ist_now.strftime("%Y-%m-%d %H:%M:%S")
    
    # Updated Format
    entry = f"{t_utc}|{t_ist}|WATCHDOG|{event_type}|{message}|[USER: External/System]\n"
    
    # FIX: UTF-8 for Emojis
    with open(config.AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(entry)
        f.flush()

def start_watchdog():
    # Watchdog now monitors the NEW location
    target = config.HONEYPOT_FILE
    log_file = config.SECURITY_LOG
    
    # Auto-create if missing (Self-Healing)
    if not os.path.exists(target):
        with open(target, "w") as f: f.write(config.BAIT_CONTENT)
    if not os.path.exists(config.AUDIT_LOG): open(config.AUDIT_LOG, "w", encoding="utf-8").close()
    if not os.path.exists(log_file): open(log_file, "w", encoding="utf-8").close()

    print(f"[JEET] WATCHDOG ACTIVE.")
    log_event("INFO", "Service Started. Baseline Hash Established.")
    
    while True:
        try:
            curr_hash = get_file_hash(target)
            
            if curr_hash != config.GOLDEN_HASH:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"!!! BREACH DETECTED AT {ts} !!!")
                
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(f"{ts} | CRITICAL | INTEGRITY FAIL | Node: Alpha\n")
                    f.flush()
                
                log_event("🔴 CRITICAL", "Integrity Check Failed (File Modified)")
                time.sleep(2) 
            
        except Exception as e:
            print(f"Error: {e}")
        
        time.sleep(1)

if __name__ == "__main__":
    start_watchdog()