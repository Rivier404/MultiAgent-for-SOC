import streamlit as st
import json
import time

st.set_page_config(page_title="AI SOC Triage Dashboard", layout="wide")
st.title("SOC Triage Alert Dashboard (Powered by Multi-Agent AI)")

col_raw, col_ai = st.columns(2)

with col_raw:
    st.subheader("Raw SIEM Logs (Input)")
    raw_placeholder = st.empty()

with col_ai:
    st.subheader("AI Analysis Report (Output)")
    ai_placeholder = st.empty()
def live_tailing():
    pass