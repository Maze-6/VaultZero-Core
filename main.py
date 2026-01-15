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
st.set_page_config(page_title="VaultZero Core", page_icon="🧊", layout="wide")

# --- 2. THEME ADAPTIVE CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Roboto+Mono:wght@400;700&display=swap');
    .title-text { font-size: 2.2rem; font-weight: 800; color: #0f172a; font-family: 'Roboto Mono', monospace; margin-bottom: 5px; border-bottom: 2px solid #0284c7; padding-bottom: 10px; }
    .subtitle-text { font-size: 1.0rem; color: #0284c7; font-family: 'Roboto Mono', monospace; margin-bottom: 25px; font-weight: bold; }
    .node-box { padding: 15px; border-radius: 6px; text-align: center; font-family: 'Roboto Mono', monospace; font-weight: bold; border: 1px solid rgba(128, 128, 128, 0.3); background-color: rgba(128, 128, 128, 0.05); box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); }
    .node-safe { border-bottom: 5px solid #10b981; } 
    .node-danger { border-bottom: 5px solid #ef4444; } 
    .node-offline { border-bottom: 5px solid #64748b; opacity: 0.7; } 
    .alert-box { background-color: #fef2f2; border: 1px solid #fecaca; border-left: 5px solid #ef4444; padding: 15px; color: #b91c1c; font-weight: bold; margin-bottom: 20px; border-radius: 4px; }
    .sidebar-name { font-weight: bold; font-size: 1.1em; margin-bottom: 0px; }
    .sidebar-role { font-size: 0.9em; opacity: 0.8; margin-top: 0px; margin-bottom: 15px; }
    footer {visibility: hidden;}
    .block-container { padding-top: 2rem; }
</style>
""", unsafe_allow_html=True)

# --- 3. SYSTEM INIT ---
db = DBHandler()
if 'node_status' not in st.session_state: st.session_state['node_status'] = [True, True, True]
if 'decrypted_file' not in st.session_state: st.session_state['decrypted_file'] = None
if 'decrypted_name' not in st.session_state: st.session_state['decrypted_name'] = ""

def log_audit(source, event_type, message):
    """Writes system events to the local audit trail."""
    t_ist = (datetime.utcnow() + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
    # Log exactly 5 columns to match the display logic
    entry = f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}|{t_ist}|{source}|{event_type}|{message}\n"
    with open(config.AUDIT_LOG, "a", encoding="utf-8") as f: f.write(entry)

def check_integrity():
    """Verifies the honeypot file against the master hash."""
    if not os.path.exists(config.HONEYPOT_FILE):
        with open(config.HONEYPOT_FILE, "w", encoding="utf-8") as f: f.write(config.BAIT_CONTENT)
        return True
    with open(config.HONEYPOT_FILE, "r", encoding="utf-8") as f:
        content = f.read()
        return hashlib.sha256("".join(content.split()).encode('utf-8')).hexdigest() == config.GOLDEN_HASH

is_compromised = not check_integrity()

# --- 4. CORE ACTIONS ---
def restore_system():
    with open(config.HONEYPOT_FILE, "w", encoding="utf-8") as f: f.write(config.BAIT_CONTENT)
    open(config.SECURITY_LOG, 'w').close()
    log_audit("ADMIN", "♻️ RESTORE", "System integrity successfully restored.")
    st.toast("System Restored")
    time.sleep(1); st.rerun()

def delete_file_permanently(filename):
    for i in range(3):
        data_p = os.path.join(config.DATA_NODES[i], f"{filename}.enc.{i}")
        key_p = os.path.join(config.KEY_NODES[i], f"{filename}.key.{i}")
        if os.path.exists(data_p): os.remove(data_p)
        if os.path.exists(key_p): os.remove(key_p)
    db.remove_file(filename)
    log_audit("CLIENT", "🔥 DATA_BURN", f"Purged asset '{filename}' and associated key shards.")
    st.session_state['decrypted_file'] = None
    st.session_state['decrypted_name'] = ""
    st.toast("Data Burned")
    time.sleep(1); st.rerun()

# --- 5. SIDEBAR ---
with st.sidebar:
    st.markdown("### 🧊 VaultZero Ops")
    st.markdown(f'<div class="sidebar-name">Mourya Reddy Udumula</div><div class="sidebar-role">(Architect)</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="sidebar-name">Jeet Anand Upadhyaya</div><div class="sidebar-role">(SecOps Lead)</div>', unsafe_allow_html=True)
    st.divider()
    if is_compromised:
        st.error("⚠️ BREACH DETECTED")
        if st.button("♻️ RESTORE INTEGRITY", type="primary"): restore_system()
    else: st.success("✅ GRID SECURE")
    
    st.divider()
    st.markdown("#### ⚡ Resilience Testing")
    c1, c2, c3 = st.columns(3)
    def toggle(i): 
        st.session_state['node_status'][i] = not st.session_state['node_status'][i]
        status = "ONLINE" if st.session_state['node_status'][i] else "OFFLINE"
        log_audit("CHAOS", "⚠️ NODE_FLIP", f"Node {i+1} transition: {status}")
    
    if c1.button(f"N1 {'🟢' if st.session_state['node_status'][0] else '🔴'}"): toggle(0); st.rerun()
    if c2.button(f"N2 {'🟢' if st.session_state['node_status'][1] else '🔴'}"): toggle(1); st.rerun()
    if c3.button(f"N3 {'🟢' if st.session_state['node_status'][2] else '🔴'}"): toggle(2); st.rerun()
    
    if st.button("🔄 System Reset"): 
        log_audit("ADMIN", "🔄 RESET", "System session state reset performed.")
        st.session_state.clear(); st.rerun()

# --- 6. MAIN UI ---
st.markdown('<div class="title-text">VaultZero: Distributed Grid</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle-text">>> DISTRIBUTED STORAGE SYSTEM | ACTIVE DEFENSE LAYER</div>', unsafe_allow_html=True)

if is_compromised:
    st.markdown("""<div class="alert-box">🚨 CRITICAL ALERT: Node Integrity Compromised. Honeypot Modified.</div>""", unsafe_allow_html=True)

nc1, nc2, nc3 = st.columns(3)
def get_style(idx):
    if not st.session_state['node_status'][idx]: return "node-offline", "OFFLINE"
    return ("node-danger", "COMPROMISED") if (idx == 0 and is_compromised) else ("node-safe", "OPERATIONAL")

s1, t1 = get_style(0); s2, t2 = get_style(1); s3, t3 = get_style(2)
nc1.markdown(f'<div class="node-box {s1}">NODE ALPHA<br>{t1}</div>', unsafe_allow_html=True)
nc2.markdown(f'<div class="node-box {s2}">NODE BETA<br>{t2}</div>', unsafe_allow_html=True)
nc3.markdown(f'<div class="node-box {s3}">NODE GAMMA<br>{t3}</div>', unsafe_allow_html=True)

st.divider()
t_arch, t_ops, t_tel, t_logs = st.tabs(["🏗️ Architecture", "📂 Grid Operations", "📊 Telemetry", "📜 Forensic Logs"])

with t_arch:
    graph = graphviz.Digraph(); graph.attr(rankdir='LR', bgcolor='transparent')
    graph.attr('node', shape='box', style='filled', fillcolor='#e0f2fe', fontname='Roboto Mono')
    graph.node('C', 'Client'); graph.node('G', 'Gateway'); graph.node('E', 'Crypto Engine')
    with graph.subgraph(name='cluster_storage') as c:
        c.attr(label='Distributed Grid', color='grey')
        c.node('N1', 'Alpha'); c.node('N2', 'Beta'); c.node('N3', 'Gamma')
    graph.edge('C', 'G'); graph.edge('G', 'E'); graph.edge('E', 'N1'); graph.edge('E', 'N2'); graph.edge('E', 'N3')
    st.graphviz_chart(graph)

with t_ops:
    col_up, col_down = st.columns(2)
    with col_up:
        st.markdown("##### 📤 Secure Ingestion")
        # clear_on_submit=True ensures the password vanishes after you click upload
        with st.form("up_form", clear_on_submit=True):
            f = st.file_uploader("Select Payload")
            k = st.text_input("Master Key (Supports 1-64 characters)", type="password", help="Input vanishes upon submission for security.")
            if st.form_submit_button("💠 Shard Data"):
                if f and k:
                    if len(k) > 64: st.error("Key too long.")
                    elif sum(st.session_state['node_status']) == 0: st.error("❌ GRID OFFLINE")
                    else:
                        t0 = time.time()
                        eng = CryptoEngine(k); d = f.getvalue(); enc = eng.encrypt_data(d)
                        chk = (len(enc)//3)+1
                        for i in range(3):
                            if st.session_state['node_status'][i]:
                                with open(os.path.join(config.DATA_NODES[i], f"{f.name}.enc.{i}"), "wb") as o: o.write(enc[i*chk:(i+1)*chk])
                        ShamirVault.distribute_key_async(k, f.name, st.session_state['node_status'])
                        dur = (time.time()-t0)*1000
                        db.add_file(f.name)
                        log_audit("CLIENT", "🔵 UPLOAD", f"Distributed asset '{f.name}' in {dur:.2f}ms")
                        
                        l = json.load(open(config.LATENCY_LOG)) if os.path.exists(config.LATENCY_LOG) else []
                        l.append({"ist": (datetime.now() + timedelta(hours=5, minutes=30)).strftime("%H:%M:%S"), "ms": dur})
                        json.dump(l, open(config.LATENCY_LOG, 'w'))
                        st.success(f"Ingestion Successful")
                        time.sleep(1); st.rerun()

    with col_down:
        st.markdown("##### 📥 Reassemble Asset")
        # The selectbox only shows files that exist in the registry (Burned files disappear automatically)
        files = db.get_files()
        # clear_on_submit=True ensures the decryption key vanishes after submission
        with st.form("dl_form", clear_on_submit=True):
            sel = st.selectbox("Stored Assets", files) if files else None
            dk = st.text_input("Decryption Key", type="password")
            if st.form_submit_button("🔓 Reassemble"):
                if sel and dk:
                    try:
                        k_recon = ShamirVault.reconstruct_key(sel, st.session_state['node_status'])
                        if k_recon.strip() == dk.strip():
                            data = b""
                            for i in range(3):
                                p = os.path.join(config.DATA_NODES[i], f"{sel}.enc.{i}")
                                if os.path.exists(p):
                                    with open(p, "rb") as r: data += r.read()
                            st.session_state['decrypted_file'] = CryptoEngine.decrypt_payload(k_recon, data)
                            st.session_state['decrypted_name'] = sel
                            log_audit("CLIENT", "🟢 DOWNLOAD", f"Successfully reassembled asset '{sel}'.")
                            st.success("Data Reconstruction Successful")
                        else: st.error("Access Denied")
                    except Exception as e: st.error(f"Error: {e}")
        
        if st.session_state.get('decrypted_file'):
            st.download_button("⬇️ Download Decrypted File", st.session_state['decrypted_file'], file_name=st.session_state['decrypted_name'], use_container_width=True)
            if st.button("🔥 Burn (Delete Forever)", type="primary", use_container_width=True):
                delete_file_permanently(st.session_state['decrypted_name'])

with t_tel:
    tc1, tc2 = st.columns([4,1])
    tc1.markdown("##### Performance Metrics")
    if tc2.button("🔥 Burn Metrics"):
        with open(config.LATENCY_LOG, 'w') as f: json.dump([], f)
        st.rerun()
    if os.path.exists(config.LATENCY_LOG):
        try:
            with open(config.LATENCY_LOG, 'r') as f: l_data = json.load(f)
            if l_data:
                fig = go.Figure(data=go.Scatter(x=[x['ist'] for x in l_data], y=[x['ms'] for x in l_data], mode='lines+markers', line=dict(color='#0284c7')))
                fig.update_layout(title="Latency (ms)", paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', height=300)
                st.plotly_chart(fig, use_container_width=True)
            else: st.info("Telemetry ledger is empty.")
        except: st.info("Ledger reset complete.")

with t_logs:
    lc1, lc2 = st.columns([4,1])
    lc1.markdown("##### Forensic Audit Trail")
    if lc2.button("🔥 Burn Logs"):
        open(config.AUDIT_LOG, 'w').close()
        st.rerun()
    if os.path.exists(config.AUDIT_LOG):
        with open(config.AUDIT_LOG, "r", encoding="utf-8") as f:
            # FIX: Only take the first 5 parts to prevent ValueError if old logs exist
            lines = [l.strip().split("|")[:5] for l in f.readlines() if "|" in l]
            if lines:
                df = pd.DataFrame(lines, columns=["UTC", "IST", "Source", "Event", "Details"]).iloc[::-1]
                st.dataframe(df, use_container_width=True, hide_index=True)
            else: st.info("No system events recorded.")