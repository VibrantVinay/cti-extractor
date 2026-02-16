import streamlit as st
import pandas as pd
from io import BytesIO
from PIL import Image
from stegano import lsb

# --- NEW IMPORTS FOR EXPANDED TOOLKIT ---
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

# --- Page Config ---
st.set_page_config(page_title="Cyber Toolkit", layout="wide")

# --- Initialize Global Session State for Dashboard & Exports ---
if "iocs_extracted" not in st.session_state:
    st.session_state.iocs_extracted = 0
if "images_encoded" not in st.session_state:
    st.session_state.images_encoded = 0
if "forensic_report" not in st.session_state:
    st.session_state.forensic_report = pd.DataFrame(columns=["Timestamp", "Tool", "Action", "Result"])

def log_to_report(tool, action, result):
    """Helper function to append actions to the global forensic report."""
    new_entry = pd.DataFrame([{
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Tool": tool,
        "Action": action,
        "Result": str(result)
    }])
    st.session_state.forensic_report = pd.concat([st.session_state.forensic_report, new_entry], ignore_index=True)

# --- Load Models ---
@st.cache_resource
def load_extractor():
    # Mocking the extractor for this example to run
    # return CTIExtractor(model_path="CyberPeace-Institute/SecureBERT-NER")
    pass

extractor = load_extractor()

# --- Global Sidebar: Export Feature ---
with st.sidebar:
    st.header("🗃️ Session Export")
    st.markdown("Download a global report of all activities performed in this session.")
    if not st.session_state.forensic_report.empty:
        csv_data = st.session_state.forensic_report.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="Download Forensic Report (CSV)",
            data=csv_data,
            file_name="session_forensic_report.csv",
            mime="text/csv",
            type="primary"
        )
        st.dataframe(st.session_state.forensic_report.tail(3), hide_index=True) # Preview last 3 actions
    else:
        st.info("No actions logged yet.")

st.title("🛡️ Advanced Cybersecurity Toolkit")

# --- Create Tabs for clean UI (Expanded) ---
tab_dash, tab1, tab2, tab_osint, tab_malware, tab_hash, tab_pass = st.tabs([
    "🏠 Dashboard", 
    "CTI Extractor", 
    "Image Steganography",
    "🔍 OSINT Analyzer", 
    "🦠 Malware Analysis", 
    "🔑 Hash Tools", 
    "🛡️ Password Gen"
])

# ==========================================
# NEW TAB: DASHBOARD
# ==========================================
with tab_dash:
    st.header("Session Overview")
    st.markdown("Welcome to your Advanced Cybersecurity Toolkit. Below are your current session metrics.")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric(label="IoCs Extracted", value=st.session_state.iocs_extracted)
    with col2:
        st.metric(label="Images Encoded", value=st.session_state.images_encoded)
    with col3:
        st.metric(label="Total Actions Logged", value=len(st.session_state.forensic_report))
        
    st.divider()
    st.info("👈 Navigate through the tabs above to use the tools, and use the sidebar to export your session report.")

# ==========================================
# TAB 1: CTI EXTRACTOR (Original Code, smoothly integrated)
# ==========================================
with tab1:
    st.header("Threat Intelligence Extractor")
    st.markdown("""
    Upload raw incident logs, threat advisories, or unstructured forensic text. 
    The BERT model will automatically extract **Indicators of Compromise (IoCs)**.
    """)

    log_text = st.text_area(
        "Paste Forensic Log / Threat Report Here:", 
        height=250, 
        placeholder="e.g., The Emotet payload communicated with 192.168.1.50 over port 80..."
    )

    if st.button("Extract IoCs", type="primary"):
        if log_text.strip():
            with st.spinner("Running deep learning inference..."):
                # Mock results for demonstration
                # results = extractor.analyze_log(log_text)
                results = [{"Entity": "192.168.1.50", "Type": "IP"}, {"Entity": "Emotet", "Type": "MALWARE"}] 
                
                if results and "error" not in results[0]:
                    st.success("Extraction Complete!")
                    df = pd.DataFrame(results)
                    st.dataframe(df, use_container_width=True)
                    
                    # Update Metrics & Logs
                    st.session_state.iocs_extracted += len(results)
                    log_to_report("CTI Extractor", "Extracted IoCs", f"Found {len(results)} entities")
                    
                elif results and "error" in results[0]:
                    st.error(results[0]["error"])
                else:
                    st.info("No threat entities detected in the provided text.")
        else:
            st.warning("Please enter text to analyze.")

# ==========================================
# TAB 2: STEGANOGRAPHY TOOL (Original Code, smoothly integrated)
# ==========================================
with tab2:
    st.header("Image Steganography (LSB)")
    st.markdown("Hide confidential text inside an image, or decode an image to reveal hidden data.")

    # Sub-tabs or Radio buttons for Encode/Decode
    steg_mode = st.radio("Select Action:", ["Encode (Hide Data)", "Decode (Reveal Data)"], horizontal=True)

    st.divider()

    if steg_mode == "Encode (Hide Data)":
        st.subheader("Hide a Message")
        
        upload_img = st.file_uploader("1. Upload Cover Image (PNG or JPG)", type=["png", "jpg", "jpeg"])
        secret_data = st.text_area("2. Enter the secret message to hide:")
        
        # 1. Initialize State
        if "encoded_image" not in st.session_state:
            st.session_state.encoded_image = None
        if "encode_success" not in st.session_state:
            st.session_state.encode_success = False
        if "error_msg" not in st.session_state:
            st.session_state.error_msg = None

        # 2. Callback Function (Runs BEFORE the page reloads)
        def process_encoding(image_file, text):
            if image_file and text:
                try:
                    # Open and process
                    img = Image.open(image_file)
                    secret_img = lsb.hide(img, text)
                    
                    # Save to bytes
                    buf = BytesIO()
                    secret_img.save(buf, format="PNG")
                    
                    # Store in state
                    st.session_state.encoded_image = buf.getvalue()
                    st.session_state.encode_success = True
                    st.session_state.error_msg = None
                    
                    # Update Metrics
                    st.session_state.images_encoded += 1
                    log_to_report("Steganography", "Encoded Image", "Success")
                except Exception as e:
                    st.session_state.encode_success = False
                    st.session_state.error_msg = f"Encoding Error: {str(e)}"
            else:
                st.session_state.encode_success = False
                st.session_state.error_msg = "Please upload an image and enter a message."

        # 3. The Button (Triggers the callback)
        st.button(
            "Encode & Generate Image", 
            type="primary", 
            on_click=process_encoding, 
            args=(upload_img, secret_data)
        )

        # 4. Safely Render UI
        if st.session_state.get("encode_success") and st.session_state.get("encoded_image"):
            st.success("Message successfully hidden!")
            
            try:
                # Re-wrap the bytes into a PIL object so Streamlit doesn't choke on raw bytes
                preview_img = Image.open(BytesIO(st.session_state.encoded_image))
                st.image(preview_img, caption="Encoded Image Preview", use_container_width=True)
                
                st.download_button(
                    label="Download Encoded Image",
                    data=st.session_state.encoded_image,
                    file_name="secret_encoded_image.png",
                    mime="image/png",
                    key="stegano_dl_btn" # Unique key prevents widget refresh bugs
                )
            except Exception as e:
                st.error(f"Frontend Render Error: {e}")
                
        elif st.session_state.get("error_msg"):
            st.error(st.session_state.error_msg)
            st.session_state.error_msg = None # Clear error after showing

    elif steg_mode == "Decode (Reveal Data)":
        st.subheader("Reveal a Message")
        
        upload_enc = st.file_uploader("1. Upload Encoded Image (PNG only)", type=["png"])
        
        if st.button("Decode Image", type="primary"):
            if upload_enc:
                try:
                    with st.spinner("Analyzing image for hidden data..."):
                        img = Image.open(upload_enc)
                        hidden_message = lsb.reveal(img)
                        
                        if hidden_message:
                            st.success("Hidden message found!")
                            st.code(hidden_message, language="text")
                            log_to_report("Steganography", "Decoded Image", "Message Found")
                        else:
                            st.warning("No hidden message found in this image.")
                except IndexError:
                    st.error("No steganographic data detected. The image might not contain a message, or it was compressed/altered.")
                except Exception as e:
                    st.error(f"An error occurred during decoding: {e}")
            else:
                st.warning("Please upload an image to decode.")

# ==========================================
# NEW TAB: OSINT & DOMAIN ANALYZER
# ==========================================
with tab_osint:
    st.header("🔍 OSINT & Domain Analyzer")
    st.markdown("Fetch WHOIS data, IP addresses, and operational status for suspicious domains.")
    
    target_domain = st.text_input("Enter Domain or URL (e.g., example.com):")
    
    if st.button("Analyze Domain", type="primary"):
        if target_domain:
            with st.spinner("Gathering Intelligence..."):
                try:
                    # Clean URL to just domain
                    domain_clean = re.sub(r'^https?://', '', target_domain).split('/')[0]
                    
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        # 1. Get IP Address
                        ip_addr = socket.gethostbyname(domain_clean)
                        st.success(f"**Resolved IP:** {ip_addr}")
                        
                        # 2. Get WHOIS Data
                        domain_info = whois.whois(domain_clean)
                        st.subheader("WHOIS Data")
                        st.write(f"**Registrar:** {domain_info.registrar}")
                        st.write(f"**Creation Date:** {domain_info.creation_date}")
                        st.write(f"**Expiration Date:** {domain_info.expiration_date}")
                        
                    with col2:
                        # 3. Check Live Status (Basic Socket Test)
                        st.subheader("Connectivity")
                        try:
                            socket.create_connection((domain_clean, 80), timeout=3)
                            st.success("Host is responding on Port 80 (HTTP).")
                        except Exception:
                            st.error("Host is NOT responding on Port 80.")
                            
                        try:
                            socket.create_connection((domain_clean, 443), timeout=3)
                            st.success("Host is responding on Port 443 (HTTPS).")
                        except Exception:
                            st.error("Host is NOT responding on Port 443.")
                            
                    log_to_report("OSINT Analyzer", "Scanned Domain", domain_clean)
                except Exception as e:
                    st.error(f"Failed to analyze domain. Ensure it is formatted correctly. Error: {e}")
        else:
            st.warning("Please enter a domain.")

# ==========================================
# NEW TAB: STATIC MALWARE ANALYSIS
# ==========================================
with tab_malware:
    st.header("🦠 Static Malware Analysis")
    st.markdown("Safely extract hashes and PE Header properties from suspicious executables (.exe, .dll) without running them.")
    
    pe_file = st.file_uploader("Upload Windows Executable", type=["exe", "dll"])
    
    if pe_file:
        file_bytes = pe_file.getvalue()
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("File Hashes")
            md5_hash = hashlib.md5(file_bytes).hexdigest()
            sha256_hash = hashlib.sha256(file_bytes).hexdigest()
            st.code(f"MD5: {md5_hash}\nSHA256: {sha256_hash}")
            
        with col2:
            st.subheader("PE Header Info")
            try:
                # Load PE from bytes safely
                pe = pefile.PE(data=file_bytes)
                compile_time = datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)
                st.write(f"**Compile Timestamp:** {compile_time}")
                st.write(f"**Number of Sections:** {pe.FILE_HEADER.NumberOfSections}")
                
                # Extract Imported DLLs
                st.write("**Imported DLLs:**")
                dlls = [entry.dll.decode('utf-8') for entry in pe.DIRECTORY_ENTRY_IMPORT] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else []
                st.dataframe(pd.DataFrame({"DLL Name": dlls}), use_container_width=True)
                
                log_to_report("Malware Analysis", "Analyzed PE File", pe_file.name)
            except Exception as e:
                st.error("File does not appear to be a valid PE file or is corrupted.")

# ==========================================
# NEW TAB: HASH IDENTIFIER
# ==========================================
with tab_hash:
    st.header("🔑 Cryptographic Hash Identifier")
    st.markdown("Identify the algorithm used to generate a hash and prepare it for analysis.")
    
    hash_input = st.text_input("Paste Hash Here:")
    
    if hash_input:
        hash_clean = hash_input.strip().lower()
        hash_len = len(hash_clean)
        
        st.subheader("Analysis Results:")
        # Check using Regex for hex characters
        if re.match(r"^[a-f0-9]+$", hash_clean):
            if hash_len == 32:
                st.success("✅ Identified as: **MD5** (or NTLM)")
                log_to_report("Hash Tool", "Identified Hash", "MD5")
            elif hash_len == 40:
                st.success("✅ Identified as: **SHA-1**")
                log_to_report("Hash Tool", "Identified Hash", "SHA-1")
            elif hash_len == 64:
                st.success("✅ Identified as: **SHA-256**")
                log_to_report("Hash Tool", "Identified Hash", "SHA-256")
            elif hash_len == 128:
                st.success("✅ Identified as: **SHA-512**")
                log_to_report("Hash Tool", "Identified Hash", "SHA-512")
            else:
                st.warning(f"Valid Hex string, but unusual length ({hash_len} chars).")
        else:
            st.error("Input contains invalid characters. Not a standard hex hash.")
            
        st.info("💡 **Next Step:** You can search for this hash on platforms like VirusTotal or crack it using hashcat.")

# ==========================================
# NEW TAB: PASSWORD GENERATOR
# ==========================================
with tab_pass:
    st.header("🛡️ Secure Password Generator & Entropy Checker")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.subheader("Constraints")
        pw_length = st.slider("Password Length", min_value=8, max_value=64, value=16)
        use_upper = st.checkbox("Include Uppercase (A-Z)", value=True)
        use_lower = st.checkbox("Include Lowercase (a-z)", value=True)
        use_digits = st.checkbox("Include Numbers (0-9)", value=True)
        use_special = st.checkbox("Include Symbols (!@#$)", value=True)
        
        if st.button("Generate Password", type="primary"):
            # Build character pool
            pool = ""
            if use_upper: pool += string.ascii_uppercase
            if use_lower: pool += string.ascii_lowercase
            if use_digits: pool += string.digits
            if use_special: pool += string.punctuation
            
            if not pool:
                st.error("Please select at least one character type.")
            else:
                # Generate Password
                secure_pw = "".join(secrets.choice(pool) for _ in range(pw_length))
                st.success("Password Generated!")
                st.code(secure_pw, language="text")
                
                # Calculate Entropy
                pool_size = len(pool)
                entropy = pw_length * math.log2(pool_size)
                
                with col2:
                    st.subheader("Strength Analysis")
                    st.metric("Entropy (bits)", f"{entropy:.1f}")
                    
                    if entropy < 40:
                        st.error("Weak: Can be cracked instantly.")
                    elif entropy < 60:
                        st.warning("Moderate: Vulnerable to dedicated cracking rigs.")
                    elif entropy < 80:
                        st.success("Strong: Very difficult to crack.")
                    else:
                        st.success("Very Strong: Cryptographically secure.")
                        
                log_to_report("Password Gen", "Generated Password", f"Length: {pw_length}, Entropy: {entropy:.1f}")
