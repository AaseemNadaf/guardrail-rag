import os
import time

import httpx
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000")


st.set_page_config(
    page_title="GuardRail RAG",
    page_icon="🛡️",
    layout='centered',
    initial_sidebar_state="expanded",
)


def get_answer(question: str) -> dict:
    """Calls the real /query endpoint. Generation can take 10-30+s, so timeout is generous."""
    try:
        resp = httpx.post(
            f"{API_BASE_URL}/query",
            json={"question": question},
            headers={"Authorization": f"Bearer {st.session_state.token}"},
            timeout=200,
        )
        if resp.status_code == 401:
            # Token expired or invalid - force back to the login screen
            st.session_state.token = None
            st.session_state.role = None
            st.rerun()
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {"answer": f"Error from API ({e.response.status_code}): {e.response.text}", "source_count": 0}
    except httpx.RequestError as e:
        return {"answer": f"Could not reach the API: {e}", "source_count": 0}


st.markdown(
    """
    <style>
        @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

        :root {
            --ink: #f2f6ff;
            --muted: #93a0bb;
            --panel: #111a2d;
            --panel-soft: #18233a;
            --line: rgba(151, 168, 202, 0.15);
            --accent: #62d8c3;
            --accent-soft: rgba(98, 216, 195, 0.12);
        }

        .stApp {
            background:
                radial-gradient(circle at 74% -10%, rgba(72, 106, 205, 0.28), transparent 34rem),
                radial-gradient(circle at 4% 38%, rgba(45, 177, 166, 0.09), transparent 26rem),
                #09101f;
            color: var(--ink);
            font-family: 'DM Sans', sans-serif;
        }

        [data-testid="stHeader"] { background: transparent; }
        [data-testid="stSidebar"] {
            background: rgba(8, 15, 29, 0.76);
            border-right: 1px solid var(--line);
        }
        [data-testid="stSidebar"] > div:first-child { padding-top: 2.2rem; }

        .brand {
            display: flex;
            align-items: center;
            gap: 0.65rem;
            margin: 0 0 2.7rem 0.15rem;
            color: var(--ink);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 1.18rem;
            font-weight: 700;
            letter-spacing: -0.03em;
        }
        .brand-mark {
            display: grid;
            width: 2rem;
            height: 2rem;
            place-items: center;
            border: 1px solid rgba(98, 216, 195, 0.35);
            border-radius: 0.65rem;
            background: var(--accent-soft);
            font-size: 1.05rem;
        }
        .sidebar-kicker {
            margin: 0 0 0.55rem;
            color: var(--muted);
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.13em;
            text-transform: uppercase;
        }
        .hero {
            padding: 3.3rem 0 2.2rem;
            text-align: center;
        }
        .hero h1 {
            margin: 0 0 2rem;
            color: var(--ink);
            font-family: 'Space Grotesk', sans-serif;
            font-size: clamp(2rem, 5vw, 3.1rem);
            letter-spacing: -0.065em;
            line-height: 1.06;
        }
        .hint-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 0.65rem;
            margin: 0 auto 2.1rem;
        }
        .hint-card {
            min-height: 5.2rem;
            padding: 0.85rem 0.95rem;
            border: 1px solid var(--line);
            border-radius: 0.8rem;
            background: rgba(17, 26, 45, 0.7);
            color: #d7e0f1;
            font-family: 'DM Sans', sans-serif;
            font-size: 0.95rem;
            font-weight: 500;
            line-height: 1.5;
            text-align: left;
        }
        .hint-icon { display: block; margin-bottom: 0.4rem; font-size: 1rem; }
        .suggestion-button {
            min-height: 5.2rem;
        }
        [data-testid="stHorizontalBlock"] .stButton button {
            min-height: 5.2rem;
            padding: 0.85rem 0.95rem;
            border: 1px solid var(--line);
            border-radius: 0.8rem;
            background: rgba(17, 26, 45, 0.7);
            color: #d7e0f1;
            font-family: 'DM Sans', sans-serif;
            font-size: 0.95rem;
            font-weight: 500;
            line-height: 1.5;
            text-align: left;
        }
        [data-testid="stHorizontalBlock"] .stButton button:hover {
            border-color: rgba(98, 216, 195, 0.55);
            color: var(--ink);
        }

        [data-testid="stChatMessage"] {
            padding: 0.85rem 0;
        }
        [data-testid="stChatMessageAvatarUser"] {
            background: #33415f;
        }
        [data-testid="stChatMessageAvatarAssistant"] {
            background: var(--accent-soft);
            color: var(--accent);
        }
        [data-testid="stChatMessageContent"] {
            color: #e8edf8;
            font-size: 0.95rem;
            line-height: 1.65;
        }
        .source-note {
            display: inline-flex;
            align-items: center;
            gap: 0.38rem;
            margin-top: 0.55rem;
            padding: 0.28rem 0.58rem;
            border: 1px solid rgba(98, 216, 195, 0.2);
            border-radius: 0.45rem;
            background: rgba(98, 216, 195, 0.07);
            color: #8bdacc;
            font-size: 0.7rem;
            font-weight: 600;
        }

        [data-testid="stChatInput"] {
            padding-bottom: 1.25rem;
        }
        [data-testid="stChatInput"] > div {
            border: 2px solid rgba(98, 216, 195, 0.42);
            border-radius: 0.9rem;
            background: rgba(17, 26, 45, 0.98);
            box-shadow: 0 0.75rem 2.5rem rgba(0, 0, 0, 0.3), 0 0 0 3px rgba(98, 216, 195, 0.08);
        }
        [data-testid="stChatInput"] textarea {
            color: var(--ink);
            font-family: 'DM Sans', sans-serif;
            font-size: 1rem;
            font-weight: 600;
        }
        [data-testid="stChatInput"] textarea::placeholder {
            color: #aebbd2;
            font-weight: 500;
        }
        [data-testid="stFileUploader"] {
            margin-top: 0.35rem;
        }
        [data-testid="stFileUploader"] section {
            border: 1px dashed rgba(98, 216, 195, 0.35);
            border-radius: 0.7rem;
            background: rgba(98, 216, 195, 0.05);
        }
        [data-testid="stFileUploader"] small {
            color: var(--muted);
        }
        .footer-note {
            padding: 0.25rem 0 1.2rem;
            color: #66738e;
            font-size: 0.7rem;
            text-align: center;
        }
        @media (max-width: 640px) {
            .hint-grid { grid-template-columns: 1fr; }
            .hero { padding-top: 2rem; }
        }
    </style>
    """,
    unsafe_allow_html=True,
)


if "token" not in st.session_state:
    st.session_state.token = None
    st.session_state.role = None

if not st.session_state.token:
    st.markdown(
        '<div class="hero"><h1>Sign in to GuardRail RAG</h1></div>',
        unsafe_allow_html=True,
    )
    with st.form("login_form"):
        login_col = st.columns([1, 2, 1])[1]
        with login_col:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", use_container_width=True)
    if submitted:
        try:
            resp = httpx.post(
                f"{API_BASE_URL}/auth/login",
                json={"username": username, "password": password},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                st.session_state.token = data["access_token"]
                st.session_state.role = data["role"]
                st.rerun()
            else:
                st.error("Invalid username or password.")
        except httpx.RequestError as e:
            st.error(f"Could not reach the API at {API_BASE_URL}: {e}")
    st.stop()


with st.sidebar:
    st.markdown(
        '<div class="brand"><span class="brand-mark">🛡️</span>GuardRail RAG</div>',
        unsafe_allow_html=True,
    )
    st.caption(f"Signed in as **{st.session_state.role}**")
    if st.button("Sign out", use_container_width=True):
        st.session_state.token = None
        st.session_state.role = None
        st.session_state.messages = []
        st.rerun()
    if st.button("＋  Start a new chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()
    st.markdown('<div class="sidebar-kicker" style="margin-top: 2rem;">Add documents</div>', unsafe_allow_html=True)
    uploaded_files = st.file_uploader(
        "Upload company documents",
        type=["pdf", "docx", "txt", "md", "csv"],
        accept_multiple_files=True,
        label_visibility="collapsed",
        help="Upload documents to connect them to the knowledge base.",
    )
    if uploaded_files:
        st.caption(f"{len(uploaded_files)} document(s) selected — upload isn't wired to the backend yet")
        for uploaded_file in uploaded_files:
            st.markdown(f"📄 {uploaded_file.name}")


if "messages" not in st.session_state:
    st.session_state.messages = []
if "pending_question" not in st.session_state:
    st.session_state.pending_question = None

typed_question = st.chat_input("Ask GuardRail about your company documents...")

if (
    not st.session_state.messages
    and not st.session_state.pending_question
    and not typed_question
):
    st.markdown(
        """
        <div class="hero">
            <h1>What can I help you find?</h1>
        </div>
        """,
        unsafe_allow_html=True,
    )
    suggestion_columns = st.columns(3)
    suggestions = [
        ("📋  Summarize our remote work policy", "Summarize our remote work policy"),
        ("🔎  Find the latest onboarding checklist", "Find the latest onboarding checklist"),
        ("💡  Explain our reimbursement process", "Explain our reimbursement process"),
    ]
    selected_question = None
    for column, (label, prompt) in zip(suggestion_columns, suggestions):
        with column:
            st.markdown('<div class="suggestion-button">', unsafe_allow_html=True)
            if st.button(label, key=f"suggestion_{prompt}", use_container_width=True):
                st.session_state.pending_question = prompt
                st.rerun()
            st.markdown("</div>", unsafe_allow_html=True)
else:
    selected_question = None


for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])
        if message["role"] == "assistant" and message.get("source_count"):
            count = message["source_count"]
            label = "document" if count == 1 else "documents"
            st.markdown(
                f'<div class="source-note">⌁ Sources: {count} {label}</div>',
                unsafe_allow_html=True,
            )


question = typed_question or selected_question or st.session_state.pending_question
st.session_state.pending_question = None

if question:
    st.session_state.messages.append({"role": "user", "content": question})
    with st.chat_message("user"):
        st.markdown(question)

    with st.chat_message("assistant"):
        with st.spinner("Thinking..."):
            response = get_answer(question)
        st.markdown(response["answer"])
        label = "document" if response["source_count"] == 1 else "documents"
        st.markdown(
            f'<div class="source-note">⌁ Sources: {response["source_count"]} {label}</div>',
            unsafe_allow_html=True,
        )
    st.session_state.messages.append(
        {
            "role": "assistant",
            "content": response["answer"],
            "source_count": response["source_count"],
        }
    )

st.markdown('<div class="footer-note">GuardRail RAG can make mistakes. Verify important information in the source documents.</div>', unsafe_allow_html=True)