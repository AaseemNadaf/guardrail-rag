"""
Layer 1 (pre-retrieval) — auth endpoint.
Issues a JWT carrying the user's role, which downstream code uses to
compute their classification clearance for RBAC-filtered retrieval.
"""
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.core.security import create_access_token
from app.services.users import authenticate_user

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str


@router.post("/login", response_model=TokenResponse)
def login(request: LoginRequest):
    user = authenticate_user(request.username, request.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )
    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return TokenResponse(access_token=token, role=user["role"])
