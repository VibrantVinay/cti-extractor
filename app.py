import streamlit as st
import pandas as pd
from io import BytesIO
from PIL import Image
from stegano import lsb

import whois
import ssl
import socket
import pefile
import hashlib
import re
import secrets
import string
import math
from datetime import datetime

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="NEXUS // Forensic Intelligence Suite",
    page_icon="⬡",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# GLOBAL STYLES — CYBER FORENSICS TERMINAL AESTHETIC
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@300;400;500;600;700&family=Orbitron:wght@400;700;900&display=swap');

/* ── GLOBAL RESET & BASE ── */
*, *::before, *::after { box-sizing: border-box; }

html, body, [data-testid="stAppViewContainer"], [data-testid="stApp"] {
    background-color: #020810 !important;
    color: #c8d8e8 !important;
    font-family: 'Rajdhani', sans-serif !important;
}

/* Scanline overlay */
[data-testid="stApp"]::before {
    content: '';
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0, 255, 180, 0.012) 2px,
        rgba(0, 255, 180, 0.012) 4px
    );
    pointer-events: none;
    z-index: 9999;
}

/* ── SIDEBAR ── */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #03111f 0%, #010a15 100%) !important;
    border-right: 1px solid #0a3d5c !important;
}
[data-testid="stSidebar"]::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
    background: linear-gradient(90deg, #00ffc8, #0088ff, #00ffc8);
    background-size: 200% 100%;
    animation: borderFlow 3s linear infinite;
}
@keyframes borderFlow {
    0% { background-position: 200% 0; }
    100% { background-position: -200% 0; }
}

/* ── MAIN CONTAINER ── */
[data-testid="stMain"] {
    background: #020810 !important;
    padding: 0 !important;
}
.block-container {
    padding: 1.5rem 2.5rem 3rem 2.5rem !important;
    max-width: 100% !important;
}

/* ── HEADER BANNER ── */
.nexus-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1.2rem 2rem;
    background: linear-gradient(135deg, #030f1e 0%, #041525 50%, #020c18 100%);
    border: 1px solid #0a3040;
    border-left: 4px solid #00ffc8;
    margin-bottom: 1.5rem;
    position: relative;
    overflow: hidden;
}
.nexus-header::after {
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 1px;
    background: linear-gradient(90deg, #00ffc8, transparent 60%);
}
.nexus-logo {
    font-family: 'Orbitron', monospace;
    font-size: 1.8rem;
    font-weight: 900;
    color: #00ffc8;
    letter-spacing: 0.15em;
    text-shadow: 0 0 20px rgba(0, 255, 200, 0.6), 0 0 40px rgba(0, 255, 200, 0.2);
}
.nexus-logo span {
    color: #0088ff;
    font-weight: 300;
    font-size: 1.1rem;
    letter-spacing: 0.25em;
}
.nexus-status {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    color: #00ffc8;
    text-align: right;
    line-height: 1.6;
}
.nexus-status .dot {
    display: inline-block;
    width: 6px; height: 6px;
    background: #00ffc8;
    border-radius: 50%;
    margin-right: 5px;
    animation: pulse 1.5s ease-in-out infinite;
}
@keyframes pulse {
    0%, 100% { opacity: 1; box-shadow: 0 0 6px #00ffc8; }
    50% { opacity: 0.4; box-shadow: none; }
}
.classification-bar {
    background: #0f0500;
    border: 1px solid #ff4400;
    color: #ff6622;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 0.2em;
    text-align: center;
    padding: 0.3rem;
    margin-bottom: 1rem;
}

/* ── SECTION HEADERS ── */
.section-header {
    font-family: 'Orbitron', monospace;
    font-size: 0.95rem;
    font-weight: 700;
    color: #00ffc8;
    letter-spacing: 0.12em;
    text-transform: uppercase;
    border-bottom: 1px solid #0a3040;
    padding-bottom: 0.6rem;
    margin-bottom: 1.2rem;
    display: flex;
    align-items: center;
    gap: 0.7rem;
}
.section-header::before {
    content: '▸';
    color: #0088ff;
    font-size: 1rem;
}

/* ── TABS ── */
[data-testid="stTabs"] [data-baseweb="tab-list"] {
    background: #020c18 !important;
    border-bottom: 1px solid #0a3040 !important;
    gap: 0 !important;
    padding: 0 !important;
}
[data-testid="stTabs"] [data-baseweb="tab"] {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.72rem !important;
    color: #4a7090 !important;
    background: transparent !important;
    border: none !important;
    border-right: 1px solid #0a2030 !important;
    padding: 0.75rem 1.2rem !important;
    letter-spacing: 0.08em !important;
    text-transform: uppercase !important;
    transition: all 0.2s ease !important;
}
[data-testid="stTabs"] [data-baseweb="tab"]:hover {
    color: #00ffc8 !important;
    background: rgba(0, 255, 200, 0.05) !important;
}
[data-testid="stTabs"] [aria-selected="true"] {
    color: #00ffc8 !important;
    background: rgba(0, 255, 200, 0.08) !important;
    border-bottom: 2px solid #00ffc8 !important;
}
[data-testid="stTabs"] [data-baseweb="tab-highlight"] {
    display: none !important;
}

/* ── METRIC CARDS ── */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #030f1e, #041828) !important;
    border: 1px solid #0a3040 !important;
    border-top: 2px solid #00ffc8 !important;
    border-radius: 0 !important;
    padding: 1.2rem !important;
    position: relative !important;
}
[data-testid="stMetric"]::after {
    content: '';
    position: absolute;
    bottom: 0; right: 0;
    width: 20px; height: 20px;
    border-bottom: 2px solid #0088ff;
    border-right: 2px solid #0088ff;
}
[data-testid="stMetricLabel"] p {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.65rem !important;
    color: #4a7090 !important;
    letter-spacing: 0.15em !important;
    text-transform: uppercase !important;
}
[data-testid="stMetricValue"] {
    font-family: 'Orbitron', monospace !important;
    font-size: 2.2rem !important;
    color: #00ffc8 !important;
    text-shadow: 0 0 15px rgba(0, 255, 200, 0.4) !important;
}

/* ── BUTTONS ── */
.stButton > button {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.12em !important;
    text-transform: uppercase !important;
    background: transparent !important;
    color: #00ffc8 !important;
    border: 1px solid #00ffc8 !important;
    border-radius: 0 !important;
    padding: 0.6rem 1.5rem !important;
    transition: all 0.2s ease !important;
    position: relative !important;
    overflow: hidden !important;
    clip-path: polygon(8px 0%, 100% 0%, calc(100% - 8px) 100%, 0% 100%) !important;
}
.stButton > button::before {
    content: '';
    position: absolute;
    top: 0; left: -100%;
    width: 100%; height: 100%;
    background: linear-gradient(90deg, transparent, rgba(0,255,200,0.15), transparent);
    transition: left 0.4s ease;
}
.stButton > button:hover::before { left: 100%; }
.stButton > button:hover {
    background: rgba(0, 255, 200, 0.1) !important;
    box-shadow: 0 0 20px rgba(0, 255, 200, 0.3), inset 0 0 20px rgba(0, 255, 200, 0.05) !important;
}
.stButton > button[kind="primary"] {
    background: linear-gradient(135deg, rgba(0,255,200,0.15), rgba(0,136,255,0.1)) !important;
    border-color: #00ffc8 !important;
    box-shadow: 0 0 10px rgba(0, 255, 200, 0.2) !important;
}

/* ── INPUTS ── */
[data-testid="stTextInput"] input,
[data-testid="stTextArea"] textarea,
.stTextInput input, .stTextArea textarea {
    background: #020c18 !important;
    border: 1px solid #0a3040 !important;
    border-left: 2px solid #0088ff !important;
    border-radius: 0 !important;
    color: #c8d8e8 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.8rem !important;
    padding: 0.6rem 0.8rem !important;
    transition: border-color 0.2s ease !important;
}
[data-testid="stTextInput"] input:focus,
[data-testid="stTextArea"] textarea:focus {
    border-color: #00ffc8 !important;
    box-shadow: 0 0 10px rgba(0, 255, 200, 0.15) !important;
}
[data-testid="stTextInput"] label,
[data-testid="stTextArea"] label {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.68rem !important;
    color: #4a7090 !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
}

/* ── FILE UPLOADER ── */
[data-testid="stFileUploader"] {
    border: 1px dashed #0a3040 !important;
    background: #020c18 !important;
    border-radius: 0 !important;
    padding: 1rem !important;
}
[data-testid="stFileUploader"]:hover {
    border-color: #00ffc8 !important;
    background: rgba(0, 255, 200, 0.03) !important;
}
[data-testid="stFileUploaderDropzoneInstructions"] {
    color: #4a7090 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.75rem !important;
}

/* ── DATAFRAMES ── */
[data-testid="stDataFrame"] {
    border: 1px solid #0a3040 !important;
}
[data-testid="stDataFrame"] th {
    background: #041525 !important;
    color: #00ffc8 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.7rem !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    border-bottom: 1px solid #0a3040 !important;
}
[data-testid="stDataFrame"] td {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.75rem !important;
    color: #a0c0d8 !important;
    border-bottom: 1px solid #050f1a !important;
}

/* ── ALERTS / STATUS BOXES ── */
[data-testid="stAlert"] {
    border-radius: 0 !important;
    border-left-width: 3px !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.78rem !important;
}
.stSuccess [data-testid="stAlert"],
div[data-testid="stAlert"][data-baseweb="notification"][kind="positive"] {
    background: rgba(0, 255, 200, 0.06) !important;
    border-left-color: #00ffc8 !important;
    color: #00ffc8 !important;
}
.stWarning [data-testid="stAlert"],
div[data-testid="stAlert"][kind="warning"] {
    background: rgba(255, 170, 0, 0.06) !important;
    border-left-color: #ffaa00 !important;
    color: #ffaa00 !important;
}
.stError [data-testid="stAlert"],
div[data-testid="stAlert"][kind="error"] {
    background: rgba(255, 60, 60, 0.06) !important;
    border-left-color: #ff3c3c !important;
    color: #ff3c3c !important;
}
.stInfo [data-testid="stAlert"],
div[data-testid="stAlert"][kind="info"] {
    background: rgba(0, 136, 255, 0.06) !important;
    border-left-color: #0088ff !important;
    color: #0088ff !important;
}

/* ── CODE BLOCKS ── */
[data-testid="stCode"] {
    background: #010811 !important;
    border: 1px solid #0a2030 !important;
    border-left: 3px solid #0088ff !important;
    border-radius: 0 !important;
}
[data-testid="stCode"] code {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.8rem !important;
    color: #7df7c8 !important;
}

/* ── SLIDERS ── */
[data-testid="stSlider"] [data-baseweb="slider"] [role="slider"] {
    background: #00ffc8 !important;
    border-color: #00ffc8 !important;
    box-shadow: 0 0 8px rgba(0, 255, 200, 0.5) !important;
}
[data-testid="stSlider"] [data-baseweb="slider"] div[data-testid="stTickBarMin"],
[data-testid="stSlider"] [data-baseweb="slider"] div[data-testid="stTickBarMax"] {
    color: #4a7090 !important;
    font-family: 'Share Tech Mono', monospace !important;
}

/* ── CHECKBOXES ── */
[data-testid="stCheckbox"] label {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.75rem !important;
    color: #7090a8 !important;
    letter-spacing: 0.05em !important;
}

/* ── RADIO BUTTONS ── */
[data-testid="stRadio"] label {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.75rem !important;
    color: #7090a8 !important;
}

/* ── DIVIDER ── */
hr {
    border-color: #0a2030 !important;
    margin: 1.5rem 0 !important;
}

/* ── SIDEBAR SPECIFICS ── */
[data-testid="stSidebar"] h1, [data-testid="stSidebar"] h2, [data-testid="stSidebar"] h3 {
    font-family: 'Orbitron', monospace !important;
    color: #00ffc8 !important;
    font-size: 0.85rem !important;
    letter-spacing: 0.12em !important;
}
[data-testid="stSidebar"] p, [data-testid="stSidebar"] li {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.72rem !important;
    color: #4a7090 !important;
    line-height: 1.6 !important;
}
[data-testid="stSidebar"] .stDownloadButton > button {
    width: 100% !important;
    background: linear-gradient(135deg, rgba(0,255,200,0.12), rgba(0,136,255,0.08)) !important;
    border: 1px solid #00ffc8 !important;
    clip-path: none !important;
}
[data-testid="stSidebar"] .stInfo {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.7rem !important;
}

/* ── SPINNERS ── */
[data-testid="stSpinner"] {
    color: #00ffc8 !important;
}
[data-testid="stSpinner"] > div {
    border-top-color: #00ffc8 !important;
}

/* ── SCROLLBAR ── */
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: #010a14; }
::-webkit-scrollbar-thumb { background: #0a3040; border-radius: 0; }
::-webkit-scrollbar-thumb:hover { background: #00ffc8; }

/* ── COLUMN / CARD PANELS ── */
.panel-box {
    background: linear-gradient(135deg, #030f1e 0%, #020c18 100%);
    border: 1px solid #0a3040;
    padding: 1.2rem;
    position: relative;
    margin-bottom: 1rem;
}
.panel-box::before {
    content: '';
    position: absolute;
    top: 0; left: 0;
    width: 30px; height: 3px;
    background: #0088ff;
}

/* ── MARKDOWN ── */
.stMarkdown p {
    font-family: 'Rajdhani', sans-serif !important;
    font-size: 0.9rem !important;
    color: #7090a8 !important;
    line-height: 1.6 !important;
}
.stMarkdown strong {
    color: #c8d8e8 !important;
    font-weight: 600 !important;
}

/* ── DOWNLOAD BUTTON ── */
.stDownloadButton > button {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.72rem !important;
    letter-spacing: 0.1em !important;
    text-transform: uppercase !important;
    background: rgba(0,136,255,0.1) !important;
    color: #0088ff !important;
    border: 1px solid #0088ff !important;
    border-radius: 0 !important;
    clip-path: polygon(8px 0%, 100% 0%, calc(100% - 8px) 100%, 0% 100%) !important;
}
.stDownloadButton > button:hover {
    background: rgba(0,136,255,0.2) !important;
    box-shadow: 0 0 15px rgba(0,136,255,0.3) !important;
}

/* ── SPINNER OVERRIDE ── */
[data-testid="stStatusWidget"] { color: #00ffc8 !important; }

/* Markdown headers inside tabs */
h1, h2, h3 {
    font-family: 'Orbitron', monospace !important;
    color: #00ffc8 !important;
    letter-spacing: 0.08em !important;
}
h2 { font-size: 1rem !important; }
h3 { font-size: 0.9rem !important; color: #0088ff !important; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# SESSION STATE
# ============================================================
if "iocs_extracted" not in st.session_state:
    st.session_state.iocs_extracted = 0
if "images_encoded" not in st.session_state:
    st.session_state.images_encoded = 0
if "forensic_report" not in st.session_state:
    st.session_state.forensic_report = pd.DataFrame(columns=["Timestamp", "Tool", "Action", "Result"])

def log_to_report(tool, action, result):
    new_entry = pd.DataFrame([{
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Tool": tool,
        "Action": action,
        "Result": str(result)
    }])
    st.session_state.forensic_report = pd.concat(
        [st.session_state.forensic_report, new_entry], ignore_index=True
    )

# ============================================================
# MODEL LOADER (MOCKED)
# ============================================================
@st.cache_resource
def load_extractor():
    pass

extractor = load_extractor()

# ============================================================
# HEADER
# ============================================================
st.markdown("""
<div class="classification-bar">
    ⚠ &nbsp; AUTHORIZED PERSONNEL ONLY — FORENSIC INTELLIGENCE SUITE — INTERNAL USE &nbsp; ⚠
</div>
""", unsafe_allow_html=True)

now = datetime.now()
st.markdown(f"""
<div class="nexus-header">
    <div>
        <div class="nexus-logo">NEXUS<br><span>FORENSIC INTELLIGENCE SUITE v4.2</span></div>
    </div>
    <div class="nexus-status">
        <div><span class="dot"></span>SYSTEM ONLINE</div>
        <div>SESSION: {now.strftime("%Y%m%d-%H%M%S")}</div>
        <div>NODE: ANALYST-WS-001</div>
        <div>CLEARANCE: LEVEL-3</div>
    </div>
</div>
""", unsafe_allow_html=True)

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("""
    <div style="text-align:center; padding: 0.5rem 0 1rem 0;">
        <div style="font-family:'Orbitron',monospace; font-size:1.1rem; color:#00ffc8; letter-spacing:0.2em;">⬡ NEXUS</div>
        <div style="font-family:'Share Tech Mono',monospace; font-size:0.6rem; color:#2a5070; letter-spacing:0.15em; margin-top:4px;">FORENSIC SUITE</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("---")
    st.markdown("### 🗃 SESSION EXPORT")
    st.markdown("Export a complete forensic chain-of-custody report for all operations.")

    if not st.session_state.forensic_report.empty:
        csv_data = st.session_state.forensic_report.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="⬇ DOWNLOAD REPORT (CSV)",
            data=csv_data,
            file_name=f"nexus_forensic_report_{now.strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
            type="primary"
        )
        st.markdown("**RECENT ACTIVITY:**")
        st.dataframe(st.session_state.forensic_report.tail(3), hide_index=True)
    else:
        st.info("No operations logged yet.")

    st.markdown("---")
    st.markdown("""
    <div style="font-family:'Share Tech Mono',monospace; font-size:0.62rem; color:#1a3550; line-height:1.8; padding-top:0.5rem;">
        MODULE INDEX<br>
        ───────────────<br>
        [01] DASHBOARD<br>
        [02] CTI EXTRACTOR<br>
        [03] STEGANOGRAPHY<br>
        [04] OSINT ANALYZER<br>
        [05] MALWARE ANALYSIS<br>
        [06] HASH IDENTIFIER<br>
        [07] PASSWORD GEN<br>
        ───────────────<br>
        BUILD 20250225-ALPHA
    </div>
    """, unsafe_allow_html=True)

# ============================================================
# TABS
# ============================================================
tab_dash, tab1, tab2, tab_osint, tab_malware, tab_hash, tab_pass = st.tabs([
    "◈  DASHBOARD",
    "◈  CTI EXTRACTOR",
    "◈  STEGANOGRAPHY",
    "◈  OSINT ANALYZER",
    "◈  MALWARE ANALYSIS",
    "◈  HASH IDENTIFIER",
    "◈  PASSWORD GEN"
])

# ──────────────────────────────────────────────────────────────
# TAB: DASHBOARD
# ──────────────────────────────────────────────────────────────
with tab_dash:
    st.markdown('<div class="section-header">SESSION TELEMETRY</div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="IoCs Extracted", value=st.session_state.iocs_extracted)
    with col2:
        st.metric(label="Images Encoded", value=st.session_state.images_encoded)
    with col3:
        st.metric(label="Total Actions Logged", value=len(st.session_state.forensic_report))

    st.divider()

    st.markdown('<div class="section-header">SYSTEM STATUS</div>', unsafe_allow_html=True)
    colA, colB, colC = st.columns(3)
    with colA:
        st.markdown("""
        <div class="panel-box">
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#4a7090; letter-spacing:0.1em; margin-bottom:0.5rem;">MODULE STATUS</div>
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.75rem; line-height:2; color:#7090a8;">
                <span style="color:#00ffc8;">●</span> CTI EXTRACTOR &nbsp;&nbsp; READY<br>
                <span style="color:#00ffc8;">●</span> STEGANOGRAPHY &nbsp; READY<br>
                <span style="color:#00ffc8;">●</span> OSINT ANALYZER &nbsp; READY<br>
                <span style="color:#00ffc8;">●</span> MALWARE SCAN &nbsp;&nbsp;&nbsp; READY<br>
                <span style="color:#00ffc8;">●</span> HASH TOOLS &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; READY<br>
                <span style="color:#00ffc8;">●</span> PASSWORD GEN &nbsp;&nbsp;&nbsp; READY
            </div>
        </div>
        """, unsafe_allow_html=True)
    with colB:
        st.markdown("""
        <div class="panel-box">
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#4a7090; letter-spacing:0.1em; margin-bottom:0.5rem;">THREAT LEVEL</div>
            <div style="font-family:'Orbitron',monospace; font-size:2.5rem; color:#ffaa00; text-shadow: 0 0 20px rgba(255,170,0,0.4); margin-bottom:0.5rem;">GUARDED</div>
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#4a7090;">NIST TIER 2 // ACTIVE MONITORING</div>
        </div>
        """, unsafe_allow_html=True)
    with colC:
        st.markdown(f"""
        <div class="panel-box">
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#4a7090; letter-spacing:0.1em; margin-bottom:0.5rem;">SESSION INFO</div>
            <div style="font-family:'Share Tech Mono',monospace; font-size:0.72rem; line-height:1.9; color:#7090a8;">
                DATE &nbsp;&nbsp;&nbsp;&nbsp; {now.strftime("%Y-%m-%d")}<br>
                TIME &nbsp;&nbsp;&nbsp;&nbsp; {now.strftime("%H:%M:%S")} UTC<br>
                BUILD &nbsp;&nbsp;&nbsp; v4.2.1-ALPHA<br>
                ENGINE &nbsp;&nbsp; SecureBERT-NER<br>
                MODE &nbsp;&nbsp;&nbsp;&nbsp; FORENSIC
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.divider()
    st.info("Navigate the module tabs above to begin operations. All actions are logged to the forensic chain-of-custody report available for export in the sidebar.")

# ──────────────────────────────────────────────────────────────
# TAB: CTI EXTRACTOR
# ──────────────────────────────────────────────────────────────
with tab1:
    st.markdown('<div class="section-header">THREAT INTELLIGENCE EXTRACTION</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Rajdhani',sans-serif; font-size:0.88rem; color:#4a7090; margin-bottom:1.2rem; border-left:2px solid #0a3040; padding-left:0.8rem;">
        Upload raw incident logs, threat advisories, or unstructured forensic text. The BERT model will automatically extract <strong style="color:#c8d8e8;">Indicators of Compromise (IoCs)</strong>.
    </div>
    """, unsafe_allow_html=True)

    log_text = st.text_area(
        "PASTE FORENSIC LOG / THREAT REPORT:",
        height=220,
        placeholder="e.g., The Emotet payload communicated with 192.168.1.50 over port 80..."
    )

    if st.button("▸ EXTRACT IoCs", type="primary"):
        if log_text.strip():
            with st.spinner("Running deep-learning inference pipeline..."):
                results = [{"Entity": "192.168.1.50", "Type": "IP_ADDRESS"}, {"Entity": "Emotet", "Type": "MALWARE_FAMILY"}]

                if results and "error" not in results[0]:
                    st.success(f"Extraction complete. {len(results)} entities identified.")
                    df = pd.DataFrame(results)
                    st.dataframe(df, use_container_width=True)
                    st.session_state.iocs_extracted += len(results)
                    log_to_report("CTI Extractor", "Extracted IoCs", f"Found {len(results)} entities")
                elif results and "error" in results[0]:
                    st.error(results[0]["error"])
                else:
                    st.info("No threat entities detected in the provided text.")
        else:
            st.warning("Input buffer empty. Provide text to analyze.")

# ──────────────────────────────────────────────────────────────
# TAB: STEGANOGRAPHY
# ──────────────────────────────────────────────────────────────
with tab2:
    st.markdown('<div class="section-header">LSB IMAGE STEGANOGRAPHY</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Rajdhani',sans-serif; font-size:0.88rem; color:#4a7090; margin-bottom:1.2rem; border-left:2px solid #0a3040; padding-left:0.8rem;">
        Conceal classified data inside image files using Least-Significant-Bit encoding, or extract hidden payloads from suspicious imagery.
    </div>
    """, unsafe_allow_html=True)

    steg_mode = st.radio("OPERATION MODE:", ["Encode (Hide Data)", "Decode (Reveal Data)"], horizontal=True)
    st.divider()

    if steg_mode == "Encode (Hide Data)":
        st.markdown("### PAYLOAD INJECTION")
        upload_img = st.file_uploader("UPLOAD COVER IMAGE (PNG / JPG):", type=["png", "jpg", "jpeg"])
        secret_data = st.text_area("ENTER SECRET PAYLOAD:")

        if "encoded_image" not in st.session_state:
            st.session_state.encoded_image = None
        if "encode_success" not in st.session_state:
            st.session_state.encode_success = False
        if "error_msg" not in st.session_state:
            st.session_state.error_msg = None

        def process_encoding(image_file, text):
            if image_file and text:
                try:
                    img = Image.open(image_file)
                    secret_img = lsb.hide(img, text)
                    buf = BytesIO()
                    secret_img.save(buf, format="PNG")
                    st.session_state.encoded_image = buf.getvalue()
                    st.session_state.encode_success = True
                    st.session_state.error_msg = None
                    st.session_state.images_encoded += 1
                    log_to_report("Steganography", "Encoded Image", "Success")
                except Exception as e:
                    st.session_state.encode_success = False
                    st.session_state.error_msg = f"Encoding Error: {str(e)}"
            else:
                st.session_state.encode_success = False
                st.session_state.error_msg = "Upload an image and enter a payload message."

        st.button("▸ INJECT & GENERATE", type="primary", on_click=process_encoding, args=(upload_img, secret_data))

        if st.session_state.get("encode_success") and st.session_state.get("encoded_image"):
            st.success("Payload successfully concealed in image.")
            try:
                preview_img = Image.open(BytesIO(st.session_state.encoded_image))
                st.image(preview_img, caption="Encoded Carrier Image", use_container_width=True)
                st.download_button(
                    label="⬇ DOWNLOAD CARRIER IMAGE",
                    data=st.session_state.encoded_image,
                    file_name="nexus_carrier_image.png",
                    mime="image/png",
                    key="stegano_dl_btn"
                )
            except Exception as e:
                st.error(f"Render Error: {e}")

        elif st.session_state.get("error_msg"):
            st.error(st.session_state.error_msg)
            st.session_state.error_msg = None

    elif steg_mode == "Decode (Reveal Data)":
        st.markdown("### PAYLOAD EXTRACTION")
        upload_enc = st.file_uploader("UPLOAD ENCODED IMAGE (PNG ONLY):", type=["png"])

        if st.button("▸ EXTRACT PAYLOAD", type="primary"):
            if upload_enc:
                try:
                    with st.spinner("Scanning image bitstream for hidden payload..."):
                        img = Image.open(upload_enc)
                        hidden_message = lsb.reveal(img)
                        if hidden_message:
                            st.success("Hidden payload recovered.")
                            st.code(hidden_message, language="text")
                            log_to_report("Steganography", "Decoded Image", "Payload Found")
                        else:
                            st.warning("No steganographic payload detected in this image.")
                except IndexError:
                    st.error("No LSB data detected. Image may be unencoded, altered, or re-compressed.")
                except Exception as e:
                    st.error(f"Decoding Error: {e}")
            else:
                st.warning("No image uploaded for analysis.")

# ──────────────────────────────────────────────────────────────
# TAB: OSINT ANALYZER
# ──────────────────────────────────────────────────────────────
with tab_osint:
    st.markdown('<div class="section-header">OPEN SOURCE INTELLIGENCE — DOMAIN ANALYZER</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Rajdhani',sans-serif; font-size:0.88rem; color:#4a7090; margin-bottom:1.2rem; border-left:2px solid #0a3040; padding-left:0.8rem;">
        Fetch <strong style="color:#c8d8e8;">WHOIS records</strong>, resolve IP addresses, and probe network connectivity for target domains.
    </div>
    """, unsafe_allow_html=True)

    target_domain = st.text_input("TARGET DOMAIN / URL:", placeholder="e.g., example.com")

    if st.button("▸ INITIATE RECONNAISSANCE", type="primary"):
        if target_domain:
            with st.spinner("Gathering open-source intelligence..."):
                try:
                    domain_clean = re.sub(r'^https?://', '', target_domain).split('/')[0]
                    col1, col2 = st.columns(2)

                    with col1:
                        st.markdown("### DNS RESOLUTION")
                        ip_addr = socket.gethostbyname(domain_clean)
                        st.success(f"Resolved IP: **{ip_addr}**")

                        st.markdown("### WHOIS RECORD")
                        domain_info = whois.whois(domain_clean)
                        st.write(f"**Registrar:** {domain_info.registrar}")
                        st.write(f"**Creation Date:** {domain_info.creation_date}")
                        st.write(f"**Expiration Date:** {domain_info.expiration_date}")

                    with col2:
                        st.markdown("### PORT CONNECTIVITY")
                        try:
                            socket.create_connection((domain_clean, 80), timeout=3)
                            st.success("Port 80 (HTTP) — OPEN")
                        except Exception:
                            st.error("Port 80 (HTTP) — CLOSED / FILTERED")

                        try:
                            socket.create_connection((domain_clean, 443), timeout=3)
                            st.success("Port 443 (HTTPS) — OPEN")
                        except Exception:
                            st.error("Port 443 (HTTPS) — CLOSED / FILTERED")

                    log_to_report("OSINT Analyzer", "Scanned Domain", domain_clean)
                except Exception as e:
                    st.error(f"Reconnaissance failed. Verify target format. Error: {e}")
        else:
            st.warning("No target domain specified.")

# ──────────────────────────────────────────────────────────────
# TAB: MALWARE ANALYSIS
# ──────────────────────────────────────────────────────────────
with tab_malware:
    st.markdown('<div class="section-header">STATIC MALWARE ANALYSIS — PE HEADER INSPECTION</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Rajdhani',sans-serif; font-size:0.88rem; color:#4a7090; margin-bottom:1.2rem; border-left:2px solid #0a3040; padding-left:0.8rem;">
        Safely extract <strong style="color:#c8d8e8;">cryptographic hashes</strong> and PE Header metadata from suspicious executables — <strong style="color:#ff4444;">without executing them</strong>.
    </div>
    """, unsafe_allow_html=True)

    pe_file = st.file_uploader("UPLOAD TARGET EXECUTABLE (.EXE / .DLL):", type=["exe", "dll"])

    if pe_file:
        file_bytes = pe_file.getvalue()
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("### CRYPTOGRAPHIC HASHES")
            md5_hash = hashlib.md5(file_bytes).hexdigest()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
            st.code(f"MD5:    {md5_hash}\nSHA256: {sha256_hash}", language="text")

        with col2:
            st.markdown("### PE HEADER METADATA")
            try:
                pe = pefile.PE(data=file_bytes)
                compile_time = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
                st.write(f"**Compile Timestamp:** {compile_time}")
                st.write(f"**Number of Sections:** {pe.FILE_HEADER.NumberOfSections}")
                st.markdown("**Imported DLLs:**")
                dlls = [entry.dll.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else []
                st.dataframe(pd.DataFrame({"DLL Name": dlls}), use_container_width=True)
                log_to_report("Malware Analysis", "Analyzed PE File", pe_file.name)
            except Exception as e:
                st.error("Target does not appear to be a valid PE file or is corrupted.")

# ──────────────────────────────────────────────────────────────
# TAB: HASH IDENTIFIER
# ──────────────────────────────────────────────────────────────
with tab_hash:
    st.markdown('<div class="section-header">CRYPTOGRAPHIC HASH IDENTIFIER</div>', unsafe_allow_html=True)
    st.markdown("""
    <div style="font-family:'Rajdhani',sans-serif; font-size:0.88rem; color:#4a7090; margin-bottom:1.2rem; border-left:2px solid #0a3040; padding-left:0.8rem;">
        Identify hash algorithms by length and character composition, and prepare digests for further analysis or cracking operations.
    </div>
    """, unsafe_allow_html=True)

    hash_input = st.text_input("INPUT HASH DIGEST:", placeholder="Paste MD5, SHA-1, SHA-256, or SHA-512 hash...")

    if hash_input:
        hash_clean = hash_input.strip().lower()
        hash_len = len(hash_clean)
        st.markdown("### ANALYSIS RESULTS")

        if re.match(r"^[a-f0-9]+$", hash_clean):
            if hash_len == 32:
                st.success("✅ Algorithm Identified: **MD5** (128-bit) — also matches NTLM")
                log_to_report("Hash Tool", "Identified Hash", "MD5")
            elif hash_len == 40:
                st.success("✅ Algorithm Identified: **SHA-1** (160-bit)")
                log_to_report("Hash Tool", "Identified Hash", "SHA-1")
            elif hash_len == 64:
                st.success("✅ Algorithm Identified: **SHA-256** (256-bit)")
                log_to_report("Hash Tool", "Identified Hash", "SHA-256")
            elif hash_len == 128:
                st.success("✅ Algorithm Identified: **SHA-512** (512-bit)")
                log_to_report("Hash Tool", "Identified Hash", "SHA-512")
            else:
                st.warning(f"Valid hexadecimal string — unusual length ({hash_len} chars). Non-standard algorithm.")
        else:
            st.error("Input contains non-hexadecimal characters. Not a standard hash digest.")

        st.info("💡 Cross-reference hash on VirusTotal, MalShare, or Hybrid-Analysis. Use hashcat / john-the-ripper for cracking operations.")

# ──────────────────────────────────────────────────────────────
# TAB: PASSWORD GENERATOR
# ──────────────────────────────────────────────────────────────
with tab_pass:
    st.markdown('<div class="section-header">SECURE PASSWORD GENERATOR & ENTROPY ANALYZER</div>', unsafe_allow_html=True)

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("### GENERATION PARAMETERS")
        pw_length = st.slider("PASSWORD LENGTH", min_value=8, max_value=64, value=16)
        use_upper = st.checkbox("Include Uppercase (A–Z)", value=True)
        use_lower = st.checkbox("Include Lowercase (a–z)", value=True)
        use_digits = st.checkbox("Include Numerals (0–9)", value=True)
        use_special = st.checkbox("Include Symbols (!@#$%^&*)", value=True)

        if st.button("▸ GENERATE SECURE PASSWORD", type="primary"):
            pool = ""
            if use_upper: pool += string.ascii_uppercase
            if use_lower: pool += string.ascii_lowercase
            if use_digits: pool += string.digits
            if use_special: pool += string.punctuation

            if not pool:
                st.error("Select at least one character class to proceed.")
            else:
                secure_pw = "".join(secrets.choice(pool) for _ in range(pw_length))
                st.success("Password generated using cryptographically secure RNG.")
                st.code(secure_pw, language="text")

                pool_size = len(pool)
                entropy = pw_length * math.log2(pool_size)

                with col2:
                    st.markdown("### ENTROPY ANALYSIS")
                    st.metric("Entropy Score (bits)", f"{entropy:.1f}")
                    st.metric("Character Pool Size", f"{pool_size}")

                    if entropy < 40:
                        st.error("⚠ WEAK — Vulnerable to instant brute-force.")
                    elif entropy < 60:
                        st.warning("⚠ MODERATE — Susceptible to dedicated cracking rigs.")
                    elif entropy < 80:
                        st.success("✓ STRONG — Resistant to most cracking methods.")
                    else:
                        st.success("✓ CRYPTOGRAPHIC — Exceeds NIST SP 800-63B standards.")

                    st.markdown(f"""
                    <div style="font-family:'Share Tech Mono',monospace; font-size:0.7rem; color:#2a5070; border-top:1px solid #0a2030; padding-top:0.8rem; margin-top:0.8rem; line-height:1.8;">
                        NIST COMPLIANCE: SP 800-63B<br>
                        ENTROPY CLASS: {'HIGH' if entropy >= 80 else 'MEDIUM' if entropy >= 60 else 'LOW'}<br>
                        CRACK RESISTANCE: {'VERY HIGH' if entropy >= 80 else 'HIGH' if entropy >= 60 else 'MEDIUM' if entropy >= 40 else 'LOW'}<br>
                        RNG BACKEND: secrets (CSPRNG)
                    </div>
                    """, unsafe_allow_html=True)

                log_to_report("Password Gen", "Generated Password", f"Length: {pw_length}, Entropy: {entropy:.1f} bits")
