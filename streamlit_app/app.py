"""
GuardRail RAG — Streamlit frontend.

UI design by Atharva. Backend integration (login gate, live /query and /audit
calls) added on top; the visual layer is his, unchanged.
"""
import os
from datetime import datetime

import httpx
import streamlit as st

API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000")
REQUEST_TIMEOUT = 200  # generation can take 10-30s+; the tunnel adds more


st.set_page_config(
    page_title="GuardRail RAG",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="expanded",
)


def _auth_headers() -> dict:
    return {"Authorization": f"Bearer {st.session_state.token}"}


def _handle_401():
    """Token expired or invalid — drop back to the login screen."""
    st.session_state.token = None
    st.session_state.role = None
    st.session_state.username = None
    st.rerun()


def get_answer(question: str) -> dict:
    """Calls the real /query endpoint."""
    try:
        resp = httpx.post(
            f"{API_BASE_URL}/query",
            json={"question": question},
            headers=_auth_headers(),
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code == 401:
            _handle_401()
        resp.raise_for_status()
        return resp.json()
    except httpx.HTTPStatusError as e:
        return {
            "answer": f"The server returned an error ({e.response.status_code}). "
                      f"If this says no index was found, run POST /ingest once.",
            "source_count": 0,
        }
    except httpx.RequestError as e:
        return {
            "answer": f"Could not reach the API at {API_BASE_URL}. If the LLM runs through a "
                      f"tunnel, check it is still up. ({type(e).__name__})",
            "source_count": 0,
        }


def get_audit_log(limit: int = 100) -> tuple[list[dict], str | None, str | None]:
    """
    Calls GET /audit. Returns (entries, scope, error).

    The backend decides scope, not this UI: admins get every entry, everyone
    else is forced to their own rows server-side. The scope string is shown to
    the user so a short log is never mistaken for an empty system.
    """
    try:
        resp = httpx.get(
            f"{API_BASE_URL}/audit",
            params={"limit": limit},
            headers=_auth_headers(),
            timeout=30,
        )
        if resp.status_code == 401:
            _handle_401()
        resp.raise_for_status()
        payload = resp.json()
        return payload.get("entries", []), payload.get("scope"), None
    except httpx.HTTPStatusError as e:
        return [], None, f"Server returned {e.response.status_code}."
    except httpx.RequestError:
        return [], None, f"Could not reach the API at {API_BASE_URL}."


def format_timestamp(raw: str | None) -> str:
    """
    The API returns ISO-8601 (2026-09-14T10:23:01.123456). Render it readably,
    but never crash the page over a timestamp — fall back to the raw string.
    """
    if not raw:
        return "unknown time"
    try:
        return datetime.fromisoformat(raw).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw


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
        .audit-title {
            margin: 2.2rem 0 0.35rem;
            color: var(--ink);
            font-family: 'Space Grotesk', sans-serif;
            font-size: 2rem;
            letter-spacing: -0.04em;
        }
        .audit-subtitle {
            margin: 0 0 1.5rem;
            color: var(--muted);
            font-size: 0.9rem;
        }
        .audit-meta {
            color: var(--muted);
            font-size: 0.78rem;
        }
        .audit-question {
            margin: 0.35rem 0 1rem;
            color: var(--ink);
            font-size: 1rem;
            font-weight: 600;
        }
        .audit-pii {
            font-size: 0.8rem;
            font-weight: 600;
        }
        .audit-pii-yes { color: #ffbd73; }
        .audit-pii-no { color: #8bdacc; }

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
        .audit-badge {
            display: inline-block;
            padding: 0.2rem 0.5rem;
            border-radius: 0.4rem;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.02em;
        }
        .audit-badge-refused {
            border: 1px solid rgba(255, 138, 138, 0.35);
            background: rgba(255, 138, 138, 0.12);
            color: #ff9f9f;
        }
        .audit-badge-answered {
            border: 1px solid rgba(98, 216, 195, 0.28);
            background: rgba(98, 216, 195, 0.1);
            color: #8bdacc;
        }
        .audit-scope {
            margin: -0.6rem 0 1.2rem;
            color: var(--muted);
            font-size: 0.78rem;
        }
    </style>
    """,
    unsafe_allow_html=True,
)


# --- login gate -------------------------------------------------------------
# Must run before the sidebar, which reads st.session_state.role.

if "token" not in st.session_state:
    st.session_state.token = None
    st.session_state.role = None
    st.session_state.username = None

if not st.session_state.token:
    st.markdown('<div class="hero"><h1>Sign in to GuardRail RAG</h1></div>', unsafe_allow_html=True)
    with st.form("login_form"):
        _, mid, _ = st.columns([1, 2, 1])
        with mid:
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Sign in", use_container_width=True)
    if submitted:
        try:
            resp = httpx.post(
                f"{API_BASE_URL}/auth/login",
                json={"username": username, "password": password},
                timeout=15,
            )
            if resp.status_code == 200:
                data = resp.json()
                st.session_state.token = data["access_token"]
                st.session_state.role = data["role"]
                st.session_state.username = username
                st.rerun()
            else:
                st.error("Invalid username or password.")
        except httpx.RequestError:
            st.error(f"Could not reach the API at {API_BASE_URL}.")
    st.stop()


# --- sidebar ----------------------------------------------------------------

with st.sidebar:
    st.markdown(
        '<div class="brand"><span class="brand-mark">🛡️</span>GuardRail RAG</div>',
        unsafe_allow_html=True,
    )
    st.caption(f"Signed in as **{st.session_state.username}** ({st.session_state.role})")
    selected_view = st.radio(
        "View",
        ["Chat", "Audit Log"],
        index=0,
        key="selected_view",
        label_visibility="collapsed",
    )
    if st.button("＋  Start a new chat", use_container_width=True):
        st.session_state.messages = []
        st.rerun()
    if st.button("Sign out", use_container_width=True):
        st.session_state.token = None
        st.session_state.role = None
        st.session_state.username = None
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
        # No backend endpoint accepts uploads yet — say so rather than implying
        # the files were indexed.
        st.caption(f"{len(uploaded_files)} document(s) selected — upload isn't wired to the backend yet")
        for uploaded_file in uploaded_files:
            st.markdown(f"📄 {uploaded_file.name}")


if "messages" not in st.session_state:
    st.session_state.messages = []
if "pending_question" not in st.session_state:
    st.session_state.pending_question = None


# --- audit view -------------------------------------------------------------

if selected_view == "Audit Log":
    st.markdown('<h1 class="audit-title">Audit Log</h1>', unsafe_allow_html=True)
    st.markdown(
        '<p class="audit-subtitle">Review recent questions, access levels, and response safeguards.</p>',
        unsafe_allow_html=True,
    )

    audit_entries, scope, error = get_audit_log()

    if error:
        st.error(f"Could not load the audit log. {error}")
        audit_entries = []
    elif scope == "own":
        st.markdown(
            '<p class="audit-scope">Showing your own activity. Administrators see all users.</p>',
            unsafe_allow_html=True,
        )
    elif scope == "all":
        st.markdown(
            '<p class="audit-scope">Showing activity for all users.</p>',
            unsafe_allow_html=True,
        )

    search_term = st.text_input("Search by user, role, or question", placeholder="Search audit log")
    if search_term:
        query = search_term.casefold()
        audit_entries = [
            entry
            for entry in audit_entries
            if query in str(entry.get("user", "")).casefold()
            or query in str(entry.get("role", "")).casefold()
            or query in str(entry.get("question", "")).casefold()
        ]

    st.caption(f"{len(audit_entries)} audit entries")

    if not audit_entries and not error:
        st.info("No activity recorded yet. Ask a question in the Chat view and it will appear here.")

    for entry in audit_entries:
        with st.container(border=True):
            refused = bool(entry.get("refused"))
            badge_class = "audit-badge-refused" if refused else "audit-badge-answered"
            badge_text = "Refused" if refused else "Answered"
            st.markdown(
                f'<div class="audit-meta">{format_timestamp(entry.get("timestamp"))} &nbsp;·&nbsp; '
                f'{entry.get("user", "unknown")} ({entry.get("role", "unknown")}) &nbsp;·&nbsp; '
                f'<span class="audit-badge {badge_class}">{badge_text}</span></div>',
                unsafe_allow_html=True,
            )
            st.markdown(
                f'<div class="audit-question">{entry.get("question", "")}</div>',
                unsafe_allow_html=True,
            )
            metric_columns = st.columns(4)
            metric_columns[0].metric("Sources", entry.get("source_count", 0))
            metric_columns[1].markdown(
                "**Allowed classifications**<br>"
                + ", ".join(entry.get("allowed_classifications") or ["—"]),
                unsafe_allow_html=True,
            )
            pii_redacted = bool(entry.get("pii_redacted"))
            pii_class = "audit-pii-yes" if pii_redacted else "audit-pii-no"
            pii_label = "Yes" if pii_redacted else "No"
            metric_columns[2].markdown(
                f'**PII redacted**<br><span class="audit-pii {pii_class}">{pii_label}</span>',
                unsafe_allow_html=True,
            )
            metric_columns[3].metric(
                "Response time", f'{float(entry.get("response_time_sec") or 0):.1f} sec'
            )

            if refused and entry.get("refusal_reason"):
                st.caption(f"Reason: {entry['refusal_reason'].replace('_', ' ')}")
            if entry.get("grounded") is not None:
                st.caption("Groundedness check: " + ("passed" if entry["grounded"] else "FLAGGED"))


# --- chat view --------------------------------------------------------------

else:
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
            source_count = response.get("source_count", 0)
            if source_count:
                label = "document" if source_count == 1 else "documents"
                st.markdown(
                    f'<div class="source-note">⌁ Sources: {source_count} {label}</div>',
                    unsafe_allow_html=True,
                )
        st.session_state.messages.append(
            {
                "role": "assistant",
                "content": response["answer"],
                "source_count": source_count,
            }
        )

st.markdown(
    '<div class="footer-note">GuardRail RAG can make mistakes. Verify important information '
    'in the source documents.</div>',
    unsafe_allow_html=True,
)