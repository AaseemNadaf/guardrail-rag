"""
FastAPI dependency for protecting routes: validates the bearer JWT and
returns the authenticated user's identity + role.

Uses HTTPBearer rather than OAuth2PasswordBearer deliberately: our
/auth/login endpoint takes a JSON body, not FastAPI's standard OAuth2
form-encoded password grant. HTTPBearer gives Swagger's Authorize
button a plain "paste your token" field that actually matches our
login flow, instead of trying (and failing) to run the OAuth2 form
flow against an endpoint that doesn't speak it.

This is what makes Layer 1 "zero trust" - every request re-validates
the token, nothing is cached or assumed from a prior request.
"""
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from app.core.security import decode_access_token

bearer_scheme = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = credentials.credentials
    try:
        payload = decode_access_token(token)
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
        return {"username": username, "role": role}
    except JWTError:
        raise credentials_exception
