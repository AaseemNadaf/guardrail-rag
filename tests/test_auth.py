"""
Tests for Layer 1: login issues a valid token, wrong credentials are
rejected, and role -> clearance mapping is correct. Doesn't require
Qdrant/Ollama running - pure auth logic.
"""
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.services.users import get_allowed_classifications


@pytest.mark.asyncio
async def test_login_success():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/auth/login", json={"username": "alice", "password": "password123"}
        )
    assert response.status_code == 200
    body = response.json()
    assert body["role"] == "hr_manager"
    assert "access_token" in body


@pytest.mark.asyncio
async def test_login_wrong_password():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/auth/login", json={"username": "alice", "password": "wrong"}
        )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_query_requires_auth():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/query", json={"question": "test"})
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_valid_token_is_accepted():
    """
    Confirms a real token from /auth/login actually authenticates on a
    protected route - i.e. execution reaches past the auth dependency
    and into the actual query logic. In this test environment Qdrant
    isn't running, so we expect a connection error from THAT, not a 401
    from auth. Getting a 401 here would mean auth itself is broken.
    """
    import qdrant_client.http.exceptions

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        login_response = await client.post(
            "/auth/login", json={"username": "bob", "password": "password123"}
        )
        token = login_response.json()["access_token"]

        try:
            response = await client.post(
                "/query",
                json={"question": "test"},
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code != 401
        except qdrant_client.http.exceptions.ResponseHandlingException:
            # Expected: no Qdrant running in this test env. Reaching this
            # point means auth succeeded and execution moved past it.
            pass


def test_intern_clearance_is_public_only():
    assert get_allowed_classifications("intern") == ["Public"]


def test_admin_clearance_includes_everything():
    allowed = get_allowed_classifications("admin")
    assert set(allowed) == {"Public", "Internal", "Confidential", "Restricted"}


def test_unknown_role_defaults_to_public():
    assert get_allowed_classifications("nonexistent_role") == ["Public"]
