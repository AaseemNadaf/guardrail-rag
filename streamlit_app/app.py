"""
GuardRail RAG — Streamlit frontend.
Placeholder — the Mac teammate's real chat UI file replaces this once ready.
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
st.info("Real chat UI pending — Mac teammate's file goes here once received.")
