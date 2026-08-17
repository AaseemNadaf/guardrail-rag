"""
GuardRail RAG — Streamlit frontend.
Week 1: placeholder that confirms the API is reachable.
M4 builds out chat UI, login, and the audit-log viewer here in later sprints.
"""
import os
import httpx
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000")

st.set_page_config(page_title="GuardRail RAG", page_icon="🛡️")
st.title("🛡️ GuardRail RAG")
st.caption("Zero-Trust RAG middleware — prototype UI")

if st.button("Check API connection"):
    try:
        resp = httpx.get(f"{API_BASE_URL}/health", timeout=5)
        st.success(f"API is up: {resp.json()}")
    except httpx.RequestError as e:
        st.error(f"Could not reach API at {API_BASE_URL}: {e}")

st.divider()
st.info("Chat interface, login, and audit log viewer will be built here in Phase 1–2.")
