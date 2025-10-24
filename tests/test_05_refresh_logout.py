# tests/test_05_refresh_logout.py
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import time
from datetime import datetime, timedelta, timezone

from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.crud import crud_refresh_token
from app.crud.crud_user import user as crud_user # Importar crud_user
from app.core import security
from app.schemas.user import UserCreate
# --- ADICIONADO: Importar settings para modificar a expiração ---
from app.core.config import settings
# --- FIM ADIÇÃO ---


pytestmark = pytest.mark.asyncio

TEST_EMAIL = "refreshlogout@example.com"
TEST_PASSWORD = "PasswordRefreshLogout123!"

async def create_and_login_user(async_client: AsyncClient, db_session: AsyncSession) -> tuple[str, str, int]:
    """Helper: Creates/resets, activates, and logs in a user, returning tokens and ID."""
    # Check if user exists first
    user_result = await db_session.execute(select(User).where(User.email == TEST_EMAIL))
    user = user_result.scalars().first()

    if not user:
        # Register if not exists
        reg_response = await async_client.post(
            "/api/v1/users/",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": "Refresh Logout User"},
        )
        assert reg_response.status_code == 201
        user_id = reg_response.json()["id"]
        user = await db_session.get(User, user_id)
        assert user is not None
    else:
        user_id = user.id
        print(f"User {TEST_EMAIL} already exists, resetting state for refresh test. ID: {user_id}")
        # Ensure password is correct
        from app.core.security import get_password_hash
        user.hashed_password = get_password_hash(TEST_PASSWORD)

    # Activate
    user.is_active = True
    user.is_verified = True
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # Log in
    login_response = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert login_response.status_code == 200, f"Login failed: {login_response.json()}"
    tokens = login_response.json()
    return tokens["access_token"], tokens["refresh_token"], user_id

@pytest.mark.asyncio
async def test_refresh_token(async_client: AsyncClient, db_session: AsyncSession, monkeypatch): # Adicionar monkeypatch
    """Test successfully refreshing an access token."""
    access_token_old, refresh_token_old, user_id = await create_and_login_user(async_client, db_session)

    # Wait a tiny bit
    time.sleep(1)

    # Refresh the token
    refresh_response = await async_client.post(
        "/api/v1/auth/refresh",
        json={"refresh_token": refresh_token_old}
    )

    # Assert success
    assert refresh_response.status_code == 200, f"Refresh failed: {refresh_response.status_code} - {refresh_response.text}"

    new_tokens = refresh_response.json()
    assert "access_token" in new_tokens
    assert "refresh_token" in new_tokens
    access_token_new = new_tokens["access_token"]
    refresh_token_new = new_tokens["refresh_token"]

    assert access_token_new != access_token_old
    assert refresh_token_new != refresh_token_old

    # Verificar que o token ANTIGO foi DELETADO (ou marcado como revogado)
    old_db_token_check = await crud_refresh_token.get_refresh_token(db_session, token=refresh_token_old)
    assert old_db_token_check is None, "Old refresh token was found after refresh"
    old_hash = crud_refresh_token.hash_token(refresh_token_old)
    old_token_in_db = await db_session.execute(select(RefreshToken).where(RefreshToken.token_hash == old_hash))
    assert old_token_in_db.scalars().first() is None, "Old token HASH still found in DB after refresh"

    # Verify the new refresh token exists and is valid in the DB
    new_db_token = await crud_refresh_token.get_refresh_token(db_session, token=refresh_token_new)
    assert new_db_token is not None, "New token not found or is revoked"
    assert new_db_token.user_id == user_id
    assert new_db_token.is_revoked is False

    # Use the new access token
    headers_new = {"Authorization": f"Bearer {access_token_new}"}
    me_response = await async_client.get("/api/v1/auth/me", headers=headers_new)
    assert me_response.status_code == 200, f"/auth/me with new token failed: {me_response.text}"
    assert me_response.json()["id"] == user_id

    # Try refreshing with the OLD (now non-existent/revoked) refresh token
    refresh_old_response = await async_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token_old}
    )
    assert refresh_old_response.status_code == 401 # Should fail

    # Try refreshing with an invalid token string
    refresh_invalid_response = await async_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": "invalidtokenstring"}
    )
    assert refresh_invalid_response.status_code == 401

    # --- CORREÇÃO: Simular token expirado modificando a configuração ---
    # Guardar valor original
    original_expire_days = settings.REFRESH_TOKEN_EXPIRE_DAYS
    # Modificar para expirar no passado (e.g., -1 dia)
    monkeypatch.setattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", -1)
    # Criar o token "expirado" usando a configuração modificada
    expired_token_str, _ = security.create_refresh_token(data={"sub": str(user_id)})
    # Restaurar valor original
    monkeypatch.setattr(settings, "REFRESH_TOKEN_EXPIRE_DAYS", original_expire_days)

    # Tentar refresh com o token criado para expirar no passado
    refresh_expired_response = await async_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": expired_token_str}
    )
    assert refresh_expired_response.status_code == 401 # JWT decode fails due to expiry
    # --- FIM CORREÇÃO ---


@pytest.mark.asyncio
async def test_logout(async_client: AsyncClient, db_session: AsyncSession):
    """Test logging out (revoking the refresh token)."""
    _, refresh_token, user_id = await create_and_login_user(async_client, db_session)

    # Verify the token exists before logout
    db_token_before = await crud_refresh_token.get_refresh_token(db_session, token=refresh_token)
    assert db_token_before is not None
    assert db_token_before.is_revoked is False

    # Logout
    logout_response = await async_client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token})
    assert logout_response.status_code == 204

    # Verify the token is revoked in DB
    db_token_after = await crud_refresh_token.get_refresh_token(db_session, token=refresh_token)
    assert db_token_after is None # get_refresh_token filters revoked ones

    # Try logging out again (idempotent)
    logout_response_again = await async_client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token})
    assert logout_response_again.status_code == 204

    # Try logging out with an invalid token
    logout_response_invalid = await async_client.post("/api/v1/auth/logout", json={"refresh_token": "invalidtoken"})
    assert logout_response_invalid.status_code == 204