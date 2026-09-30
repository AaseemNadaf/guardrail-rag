"""
Audit log read endpoint.

Access rule: admins see every entry; everyone else sees only their own.

This matters more than it looks. Question text can itself carry sensitive
information ("what is <name>'s termination date?"), so an unrestricted audit
endpoint would leak through the audit channel - a low-clearance user could
read what high-clearance users are asking about, and infer the existence and
subject of documents they can't retrieve. Scoping non-admins to their own
rows closes that side channel while keeping the log useful for oversight.
"""
import logging

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_session
from app.core.dependencies import get_current_user
from app.services.audit import list_entries

router = APIRouter(prefix="/audit", tags=["audit"])
logger = logging.getLogger("guardrail.audit")


@router.get("")
def get_audit_log(
    limit: int = Query(100, ge=1, le=1000),
    username: str | None = None,
    role: str | None = None,
    current_user: dict = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    """
    Returns audit entries, newest first.

    Admins may filter by username/role. Non-admins are forced to their own
    username regardless of what they pass - the filter is overridden server
    side rather than validated, so a crafted query can't widen the scope.
    """
    is_admin = current_user["role"] == "admin"

    if is_admin:
        effective_username = username
        effective_role = role
    else:
        effective_username = current_user["username"]
        effective_role = None
        if username and username != current_user["username"]:
            logger.info(
                "Audit scope override — user=%s attempted to read entries for user=%s",
                current_user["username"], username,
            )

    entries = list_entries(
        session,
        limit=limit,
        username=effective_username,
        role=effective_role,
    )

    return {
        "scope": "all" if is_admin else "own",
        "count": len(entries),
        "entries": [e.to_dict() for e in entries],
    }
