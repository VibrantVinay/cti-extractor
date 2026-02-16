import streamlit as st
import pandas as pd
from io import BytesIO
from PIL import Image
from stegano import lsb

# Assuming CTIExtractor is in extractor.py
# from extractor import CTIExtractor

# --- Page Config ---
st.set_page_config(page_title="Cyber Toolkit", layout="wide")

# --- Load Models ---
@st.cache_resource
def load_extractor():
    # Mocking the extractor for this example to run
    # return CTIExtractor(model_path="CyberPeace-Institute/SecureBERT-NER")
    pass

extractor = load_extractor()

st.title("🛡️ Advanced Cybersecurity Toolkit")

# --- Create Tabs for clean UI ---
tab1, tab2 = st.tabs(["CTI Extractor", "Image Steganography"])

# ==========================================
# TAB 1: CTI EXTRACTOR
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
                elif results and "error" in results[0]:
                    st.error(results[0]["error"])
                else:
                    st.info("No threat entities detected in the provided text.")
        else:
            st.warning("Please enter text to analyze.")

# ==========================================
# TAB 2: STEGANOGRAPHY TOOL
# ==========================================
with tab2:
    st.header("🕵️ Image Steganography (LSB)")
    st.markdown("Hide confidential text inside an image, or decode an image to reveal hidden data.")

    # Sub-tabs or Radio buttons for Encode/Decode
    steg_mode = st.radio("Select Action:", ["Encode (Hide Data)", "Decode (Reveal Data)"], horizontal=True)

    st.divider()

    if steg_mode == "Encode (Hide Data)":
        st.subheader("Hide a Message")
        
        upload_img = st.file_uploader("1. Upload Cover Image (PNG or JPG)", type=["png", "jpg", "jpeg"])
        secret_data = st.text_area("2. Enter the secret message to hide:")
        
        # 1. Initialize TWO session states to anchor the data and the UI
        if "encoded_image" not in st.session_state:
            st.session_state.encoded_image = None
        if "encode_success" not in st.session_state:
            st.session_state.encode_success = False

        # 2. The Button Logic (Processes data and flips the success flag to True)
        if st.button("Encode & Generate Image", type="primary"):
            if upload_img and secret_data:
                try:
                    with st.spinner("Encoding message into image..."):
                        img = Image.open(upload_img)
                        secret_img = lsb.hide(img, secret_data)
                        
                        buf = BytesIO()
                        secret_img.save(buf, format="PNG")
                        
                        # Lock the image and success state into memory
                        st.session_state.encoded_image = buf.getvalue()
                        st.session_state.encode_success = True
                except Exception as e:
                    st.error(f"An error occurred during encoding: {e}")
                    st.session_state.encode_success = False # Reset on failure
            else:
                st.warning("Please upload an image and enter a message to hide.")

        # 3. The Display Logic (Strictly separated from the button's indentation!)
        if st.session_state.get("encode_success") and st.session_state.get("encoded_image"):
            # Because this is outside the button block, it will survive page reloads
            st.success("Message successfully hidden!")
            st.image(st.session_state.encoded_image, caption="Encoded Image Preview", use_container_width=True)
            
            st.download_button(
                label="Download Encoded Image",
                data=st.session_state.encoded_image,
                file_name="secret_encoded_image.png",
                mime="image/png"
            )

    elif steg_mode == "Decode (Reveal Data)":
        st.subheader("Reveal a Message")
        
        # Note: We only accept PNG here because JPGs would have lost the data
        upload_enc = st.file_uploader("1. Upload Encoded Image (PNG only)", type=["png"])
        
        if st.button("Decode Image", type="primary"):
            if upload_enc:
                try:
                    with st.spinner("Analyzing image for hidden data..."):
                        img = Image.open(upload_enc)
                        # Reveal the hidden message
                        hidden_message = lsb.reveal(img)
                        
                        if hidden_message:
                            st.success("Hidden message found!")
                            # Using code block to make the extracted text easy to copy
                            st.code(hidden_message, language="text")
                        else:
                            st.warning("No hidden message found in this image.")
                except IndexError:
                    st.error("No steganographic data detected. The image might not contain a message, or it was compressed/altered.")
                except Exception as e:
                    st.error(f"An error occurred during decoding: {e}")
            else:
                st.warning("Please upload an image to decode.")
