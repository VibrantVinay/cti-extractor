import streamlit as st
import pandas as pd
from extractor import CTIExtractor

# Page Config
st.set_page_config(page_title="CTI Extractor", layout="wide")

# Load the model once and cache it
@st.cache_resource
def load_extractor():
    return CTIExtractor(model_path="cisco-ai/SecureBERT2.0-NER")

extractor = load_extractor()

# UI Layout
st.title("🛡️ Cyber Threat Intelligence Extractor")
st.markdown("""
Upload raw incident logs, threat advisories, or unstructured forensic text. 
The BERT model will automatically extract **Indicators of Compromise (IoCs)**.
""")

# Input
log_text = st.text_area("Paste Forensic Log / Threat Report Here:", height=250, 
                        placeholder="e.g., The Emotet payload communicated with 192.168.1.50 over port 80...")

if st.button("Extract IoCs", type="primary"):
    if log_text.strip():
        with st.spinner("Running deep learning inference..."):
            results = extractor.analyze_log(log_text)
            
            if results and "error" not in results[0]:
                st.success("Extraction Complete!")
                
                # Display results nicely in a table
                df = pd.DataFrame(results)
                st.dataframe(df, use_container_width=True)
                
            elif results and "error" in results[0]:
                st.error(results[0]["error"])
            else:
                st.info("No threat entities detected in the provided text.")
    else:
        st.warning("Please enter text to analyze.")
