"""
Mock user store and role -> classification clearance mapping.

This is intentionally a hardcoded dict for now, not a real DB table -
swapping this for SQLite (already in the stack) is a clean follow-up
once M3's real dataset and more roles are finalized. The interface
(authenticate_user, get_allowed_classifications) is what the rest of
the app depends on, so that swap won't ripple outward.
"""
from app.core.security import get_password_hash, verify_password

# Ordered lowest -> highest clearance. Index position IS the clearance level.
CLASSIFICATION_ORDER = ["Public", "Internal", "Confidential", "Restricted"]

ROLE_CLEARANCE = {
    "admin": "Restricted",
    "hr_manager": "Confidential",
    "engineer": "Internal",
    "intern": "Public",
}

# Demo credentials - password is "password123" for all, for local dev/testing only.
# Replace with real user management before anything resembling production use.
MOCK_USERS = {
    "alice": {
        "username": "alice",
        "role": "hr_manager",
        "hashed_password": get_password_hash("password123"),
    },
    "bob": {
        "username": "bob",
        "role": "engineer",
        "hashed_password": get_password_hash("password123"),
    },
    "carol": {
        "username": "carol",
        "role": "intern",
        "hashed_password": get_password_hash("password123"),
    },
    "admin": {
        "username": "admin",
        "role": "admin",
        "hashed_password": get_password_hash("password123"),
    },
}


def authenticate_user(username: str, password: str) -> dict | None:
    user = MOCK_USERS.get(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return None
    return user


def get_allowed_classifications(role: str) -> list[str]:
    """Returns every classification level this role is cleared to see (inclusive)."""
    clearance = ROLE_CLEARANCE.get(role, "Public")
    max_idx = CLASSIFICATION_ORDER.index(clearance)
    return CLASSIFICATION_ORDER[: max_idx + 1]
