import streamlit as st
import pandas as pd
import os
import time
import json
import hashlib
import graphviz
import plotly.graph_objects as go
from datetime import datetime, timedelta
from crypto_engine import CryptoEngine
from shamir_handler import ShamirVault
from db_handler import DBHandler
import config

# --- 1. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="VaultZero Grid", 
    page_icon="🧊", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- 2. CUSTOM "HIGH CONTRAST" CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap');
    
    /* Headers */
    .title-text { 
        font-size: 2.2rem; 
        font-weight: 800; 
        color: #0f172a; 
        font-family: 'Roboto Mono', monospace; 
        margin-bottom: 5px; 
    }
    .subtitle-text { 
        font-size: 1.0rem; 
        color: #0284c7; 
        font-family: 'Roboto Mono', monospace; 
        margin-bottom: 25px; 
        font-weight: bold;
    }
    
    /* Node Cards */
    .node-box { 
        padding: 15px; 
        border-radius: 6px; 
        text-align: center; 
        font-family: 'Roboto Mono', monospace; 
        font-weight: bold; 
        border: 1px solid #cbd5e1; 
        background-color: #f8fafc; 
        color: #334155; 
        box-shadow: 2px 2px 0px rgba(0,0,0,0.1);
    }
    .node-safe { border-bottom: 5px solid #10b981; } 
    .node-danger { border-bottom: 5px solid #ef4444; } 
    .node-offline { border-bottom: 5px solid #64748b; background-color: #e2e8f0; } 
    
    /* Sidebar Text */
    .sidebar-name { font-weight: bold; font-size: 1.1em; margin-bottom: 0px; }
    .sidebar-role { font-size: 0.9em; opacity: 0.8; margin-top: 0px; margin-bottom: 15px; }

    /* Clean UI but keep MainMenu visible for Rerun */
    footer {visibility: hidden;}
    .block-container { padding-top: 2rem; }
    .stButton>button { font-weight: bold; border-radius: 4px; }
    
    /* Alert Box */
    .alert-box { 
        background-color: #fef2f2; 
        border: 1px solid #fecaca;
        border-left: 5px solid #ef4444; 
        padding: 15px; 
        color: #b91c1c; 
        font-weight: bold; 
        margin-bottom: 20px; 
        border-radius: 4px; 
    }
</style>
""", unsafe_allow_html=True)

# --- 3. INIT SYSTEM ---
db = DBHandler()
if 'node_status' not in st.session_state: st.session_state['node_status'] = [True, True, True]
if 'decrypted_file' not in st.session_state: st.session_state['decrypted_file'] = None
if 'decrypted_name' not in st.session_state: st.session_state['decrypted_name'] = ""

# --- 4. HELPER FUNCTIONS ---
def get_dual_time():
    utc_now = datetime.utcnow()
    ist_now = utc_now + timedelta(hours=5, minutes=30)
    return {"utc": utc_now.strftime("%Y-%m-%d %H:%M:%S"), "ist": ist_now.strftime("%Y-%m-%d %H:%M:%S")}

def log_audit(source, event_type, message):
    t = get_dual_time()
    entry = f"{t['utc']}|{t['ist']}|{source}|{event_type}|{message}|[USER: Admin]\n"
    with open(config.AUDIT_LOG, "a", encoding="utf-8") as f: f.write(entry)

# --- 5. INITIALIZATION & SELF-HEALING ---
# 1. Init Telemetry
if not os.path.exists(config.LATENCY_LOG) or os.stat(config.LATENCY_LOG).st_size == 0:
    t = get_dual_time()
    init_data = [{"utc": t['utc'], "ist": t['ist'], "ms": 5.0}]
    with open(config.LATENCY_LOG, 'w') as f: json.dump(init_data, f)

# 2. Init Logs
if not os.path.exists(config.AUDIT_LOG):
    log_audit("SYSTEM", "⚡ BOOT", "VaultZero Grid Initialized.")

# 3. SELF-HEALING HONEYPOT
# Automatically creates the trap file in Node 1 if it doesn't exist
if not os.path.exists(config.HONEYPOT_FILE):
    try:
        with open(config.HONEYPOT_FILE, "w") as f: f.write(config.BAIT_CONTENT)
        log_audit("SYSTEM", "🛡️ DEFENSE_INIT", "Honeypot deployed to Data Node 1.")
    except Exception as e:
        pass 

# 4. INTEGRITY CHECK
is_compromised = False
if os.path.exists(config.HONEYPOT_FILE):
    with open(config.HONEYPOT_FILE, "r") as f:
        if hashlib.sha256(f.read().encode()).hexdigest() != config.GOLDEN_HASH:
            is_compromised = True
            try:
                log_needed = True
                if os.path.exists(config.AUDIT_LOG):
                    with open(config.AUDIT_LOG, "r", encoding="utf-8") as lf:
                        lines = lf.readlines()
                        if lines and "INTEGRITY_FAIL" in lines[-1]:
                            log_needed = False
                if log_needed:
                    log_audit("SYSTEM", "🔴 INTEGRITY_FAIL", "Honeypot modification detected on Node 1.")
            except: pass

# --- 6. ACTIONS ---
def restore_system():
    with open(config.HONEYPOT_FILE, "w") as f: f.write(config.BAIT_CONTENT)
    log_audit("ADMIN", "♻️ RESTORE", "System integrity restored.")
    st.toast("System Sanitized")
    time.sleep(1)
    st.rerun()

def delete_file_permanently(filename):
    for i in range(3):
        try: os.remove(os.path.join(config.DATA_NODES[i], f"{filename}.enc.{i}"))
        except: pass
        try: os.remove(os.path.join(config.KEY_NODES[i], f"{filename}.key.{i}"))
        except: pass
    db.remove_file(filename)
    log_audit("CLIENT", "🔥 DATA_BURN", f"Permanent deletion of '{filename}' executed.")
    st.session_state['decrypted_file'] = None
    st.toast("File Securely Wiped")
    time.sleep(1)
    st.rerun()

# --- 7. SIDEBAR ---
with st.sidebar:
    st.markdown("### 🧊 VaultZero Ops")
    
    st.markdown('<div class="sidebar-name">Mourya Reddy Udumula</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-role">(System Architect)</div>', unsafe_allow_html=True)
    
    st.markdown('<div class="sidebar-name">Jeet Anand Upadhyaya</div>', unsafe_allow_html=True)
    st.markdown('<div class="sidebar-role">(SecOps Lead)</div>', unsafe_allow_html=True)
    
    st.divider()
    st.markdown("#### 🛠️ Grid Controls")
    
    if is_compromised:
        st.error("⚠️ BREACH DETECTED")
        if st.button("♻️ FLUSH & RESTORE", type="primary"): restore_system()
    else:
        st.success("✅ GRID SECURE")
        
    st.markdown("---")
    st.markdown("#### ⚡ Resilience Testing")
    def toggle(i): 
        st.session_state['node_status'][i] = not st.session_state['node_status'][i]
        status = "OFFLINE" if not st.session_state['node_status'][i] else "ONLINE"
        log_audit("CHAOS", "⚠️ NODE_FLIP", f"Node {i+1} status set to {status}")
    
    c1, c2, c3 = st.columns(3)
    with c1: st.button(f"N1 {'🟢' if st.session_state['node_status'][0] else '🔴'}", key="n1", on_click=toggle, args=(0,))
    with c2: st.button(f"N2 {'🟢' if st.session_state['node_status'][1] else '🔴'}", key="n2", on_click=toggle, args=(1,))
    with c3: st.button(f"N3 {'🟢' if st.session_state['node_status'][2] else '🔴'}", key="n3", on_click=toggle, args=(2,))
    
    st.markdown("")
    if any(st.session_state['node_status']):
        if st.button("⛔ KILL SWITCH", type="primary", use_container_width=True):
            st.session_state['node_status'] = [False, False, False]
            log_audit("CHAOS", "⛔ LOCKDOWN", "All Nodes Down.")
            st.rerun()
    else:
        if st.button("🟢 REBOOT GRID", type="primary", use_container_width=True):
            st.session_state['node_status'] = [True, True, True]
            log_audit("CHAOS", "🟢 NETWORK_UP", "Grid Rebooted.")
            st.rerun()

# --- 8. MAIN UI ---
st.markdown('<div class="title-text">VaultZero: Distributed Grid</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle-text">>> Fault-Tolerant Storage with Active Defense Protocols</div>', unsafe_allow_html=True)

if is_compromised:
    st.markdown("""<div class="alert-box">🚨 CRITICAL ALERT: Node Integrity Compromised. Active Defense Protocols Engaged.</div>""", unsafe_allow_html=True)

c1, c2, c3 = st.columns(3)
def get_node_style(idx):
    if not st.session_state['node_status'][idx]: return "node-offline", "DISCONNECTED"
    if idx == 0 and is_compromised: return "node-danger", "COMPROMISED"
    return "node-safe", "OPERATIONAL"

s1, t1_txt = get_node_style(0); s2, t2_txt = get_node_style(1); s3, t3_txt = get_node_style(2)
with c1: st.markdown(f'<div class="node-box {s1}">NODE ALPHA<br>[STATUS: {t1_txt}]</div>', unsafe_allow_html=True)
with c2: st.markdown(f'<div class="node-box {s2}">NODE BETA<br>[STATUS: {t2_txt}]</div>', unsafe_allow_html=True)
with c3: st.markdown(f'<div class="node-box {s3}">NODE GAMMA<br>[STATUS: {t3_txt}]</div>', unsafe_allow_html=True)

st.divider()

t1, t2, t3, t4 = st.tabs(["🏗️ Architecture", "📂 Grid Operations", "📊 Network Telemetry", "📜 Forensic Logs"])

with t1:
    st.markdown("##### 💠 System Topology")
    graph = graphviz.Digraph()
    graph.attr(rankdir='LR', bgcolor='transparent') 
    graph.attr('node', shape='box', style='filled', fillcolor='#e0f2fe', fontname='Roboto Mono')
    graph.node('C', 'Client App')
    graph.node('G', 'API Gateway')
    graph.node('E', 'Crypto Engine')
    with graph.subgraph(name='cluster_storage') as c:
        c.attr(label='Distributed Grid', color='grey')
        c.node('N1', 'Node Alpha')
        c.node('N2', 'Node Beta')
        c.node('N3', 'Node Gamma')
    graph.edge('C', 'G'); graph.edge('G', 'E')
    graph.edge('E', 'N1', label='Shard 1')
    graph.edge('E', 'N2', label='Shard 2')
    graph.edge('E', 'N3', label='Shard 3')
    st.graphviz_chart(graph)
    st.info("Architecture: Logical separation of Data and Keys via Shamir's Secret Sharing (k=2, n=3).")

with t2:
    c_op1, c_op2 = st.columns(2)
    with c_op1:
        st.markdown("##### 📤 Secure Ingestion")
        with st.form("upload_form", clear_on_submit=True):
            f = st.file_uploader("Select Payload (Max 200MB)")
            
            # UPDATED: Added help tooltip for technical justification
            k = st.text_input(
                "Master Key", 
                type="password", 
                help="PBKDF2 Key Stretching allows any length input to generate a secure 256-bit key."
            )
            
            if st.form_submit_button("💠 Shard & Distribute"):
                if not f or not k:
                    st.warning("Please provide a file and a master key.")
                elif sum(st.session_state['node_status']) == 0:
                    st.error("❌ GRID OFFLINE")
                else:
                    try:
                        t0 = time.time()
                        eng = CryptoEngine(k) 
                        d = f.getvalue()
                        enc = eng.encrypt_data(d)
                        chk = (len(enc)//3)+1
                        for i in range(3):
                            if st.session_state['node_status'][i]:
                                with open(os.path.join(config.DATA_NODES[i], f"{f.name}.enc.{i}"), "wb") as o: o.write(enc[i*chk:(i+1)*chk])
                        ShamirVault.distribute_key_async(k, f.name, st.session_state['node_status'])
                        dur = (time.time()-t0)*1000
                        db.add_file(f.name)
                        
                        l = json.load(open(config.LATENCY_LOG))
                        times = get_dual_time()
                        l.append({"utc": times['utc'], "ist": times['ist'], "ms": dur})
                        json.dump(l, open(config.LATENCY_LOG, 'w'))
                        
                        log_audit("CLIENT", "🔵 UPLOAD", f"Payload '{f.name}' distributed in {dur:.2f}ms")
                        st.success(f"Ingestion Complete. Latency: {dur:.2f}ms")
                        time.sleep(1)
                        st.rerun() 
                    except Exception as e: st.error(f"Error: {e}")

    with c_op2:
        st.markdown("##### 📥 Payload Reconstruction")
        files = db.get_files()
        with st.form("recover_form", clear_on_submit=True):
            sel = st.selectbox("Target Asset", files) if files else None
            dk = st.text_input("Decryption Key", type="password")
            if st.form_submit_button("🔓 Reassemble"):
                if not sel:
                    st.warning("No file selected.")
                elif sum(st.session_state['node_status']) < 2:
                    st.error("❌ QUORUM FAILURE (Need 2/3 Nodes)")
                else:
                    try:
                        k_recon = ShamirVault.reconstruct_key(sel, st.session_state['node_status'])
                        if k_recon.strip() == dk.strip():
                            data = b""
                            for i in range(3):
                                p = os.path.join(config.DATA_NODES[i], f"{sel}.enc.{i}")
                                if os.path.exists(p):
                                    with open(p, "rb") as r: data += r.read()
                            
                            final = CryptoEngine.decrypt_payload(k_recon, data)
                            st.session_state['decrypted_file'] = final
                            st.session_state['decrypted_name'] = sel
                            log_audit("CLIENT", "🟢 DOWNLOAD", f"Asset '{sel}' reassembled.")
                            st.success("Reassembly Successful!")
                        else: 
                            log_audit("CLIENT", "⛔ ACCESS_DENIED", f"Invalid Key for '{sel}'")
                            st.error("Access Denied: Invalid Credentials")
                    except Exception as e: 
                        log_audit("SYSTEM", "❌ ERROR", f"Reassembly crash: {e}")
                        st.error(f"System Error: {e}")
        
        if st.session_state['decrypted_file']:
            st.download_button("⬇️ Download Asset", st.session_state['decrypted_file'], st.session_state['decrypted_name'], use_container_width=True)
            if st.button("🔥 Secure Wipe", type="primary", use_container_width=True):
                delete_file_permanently(st.session_state['decrypted_name'])

with t3:
    c_met_head, c_met_btn = st.columns([4, 1])
    with c_met_head: st.markdown("##### Latency Telemetry")
    with c_met_btn:
        if st.button("🧹 Reset Metrics"): 
            t = get_dual_time()
            init_data = [{"utc": t['utc'], "ist": t['ist'], "ms": 5.0}]
            with open(config.LATENCY_LOG, 'w') as f: json.dump(init_data, f)
            st.rerun()

    if os.path.exists(config.LATENCY_LOG):
        l = json.load(open(config.LATENCY_LOG))
        times_ist = [x['ist'] for x in l]
        vals = [x['ms'] for x in l]
        
        fig = go.Figure(data=go.Scatter(x=times_ist, y=vals, mode='lines+markers', line=dict(color='#0284c7', width=3)))
        fig.update_layout(
            title="Encryption Overhead (ms)", 
            xaxis_title="Timestamp (IST)", 
            yaxis_title="Time (ms)", 
            height=300,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)'
        )
        st.plotly_chart(fig, use_container_width=True)
        
        with st.expander("View Raw Telemetry"):
            st.dataframe(pd.DataFrame(l), use_container_width=True, hide_index=True)
    else:
        st.info("Initializing telemetry stream...")

with t4:
    c_hdr, c_btn = st.columns([4, 1])
    with c_hdr: st.markdown("##### Forensic Audit Trail")
    with c_btn: 
        if st.button("🗑️ Purge Logs"): 
            open(config.AUDIT_LOG, 'w').close()
            st.rerun()

    if os.path.exists(config.AUDIT_LOG):
        try:
            with open(config.AUDIT_LOG, "r", encoding="utf-8") as f: lines = f.readlines()
            data = []
            for line in lines:
                parts = line.strip().split("|")
                if len(parts) >= 6:
                    data.append({
                        "UTC": parts[0],
                        "IST": parts[1],
                        "Source": parts[2],
                        "Event": parts[3],
                        "Details": parts[4],
                        "User": parts[5]
                    })
            if data:
                df = pd.DataFrame(data).iloc[::-1]
                st.dataframe(df, use_container_width=True, hide_index=True)
            else: st.info("Ledger initialized. Waiting for events.")
        except: st.warning("Log integrity check failed.")
    else: st.info("No logs generated yet.")