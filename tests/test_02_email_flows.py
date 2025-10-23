# tests/test_02_email_flows.py
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch  # Keep patch
import hashlib
from datetime import datetime, timezone

from app.models.user import User
from app.core.security import get_password_hash  # Keep this

pytestmark = pytest.mark.asyncio

TEST_EMAIL = "emailflow@example.com"
TEST_PASSWORD = "PasswordFlow123!"
NEW_PASSWORD = "NewPasswordFlow456!"


# --- FIX THE PATCH PATHS ---
@pytest.fixture(autouse=True)
def mock_email_service():
    # Patch where the function is LOOKED UP when called by the endpoint
    with (
        patch(
            "app.api.endpoints.users.send_verification_email", return_value=True
        ) as mock_verify,
        patch(
            "app.api.endpoints.auth.send_password_reset_email", return_value=True
        ) as mock_reset,
    ):
        yield mock_verify, mock_reset


# --- END FIX ---


# ...(rest of the file remains the same)...
async def test_email_verification_flow(
    async_client: AsyncClient, db_session: AsyncSession, mock_email_service
):
    """Testa o fluxo completo de verificação de email."""
    mock_verify, _ = mock_email_service

    # 1. Registrar usuário (deve enviar email mockado)
    response = await async_client.post(
        "/api/v1/users/",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "full_name": "Email Verify User",
        },
    )
    assert response.status_code == 201
    user_data = response.json()
    user_id = user_data["id"]
    mock_verify.assert_called_once()  # Now this should work
    # Handle potential KeyError if call_args is empty (though assert_called_once should prevent this)
    try:
        verification_token = mock_verify.call_args[1]["verification_token"]
    except (TypeError, KeyError, IndexError):
        pytest.fail("Could not retrieve verification_token from mocked email call")

    # Verificar no BD que o usuário está inativo/não verificado
    user = await db_session.get(User, user_id)
    assert user is not None
    assert user.is_active is False
    assert user.is_verified is False
    assert (
        user.verification_token_hash
        == hashlib.sha256(verification_token.encode("utf-8")).hexdigest()
    )

    # 2. Tentar logar (deve falhar)
    login_response = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert login_response.status_code == 400
    assert "Conta inativa ou e-mail não verificado" in login_response.json()["detail"]

    # 3. Usar o token de verificação (deve ativar o usuário)
    verify_response = await async_client.get(
        f"/api/v1/auth/verify-email/{verification_token}"
    )
    assert verify_response.status_code == 200
    verified_user_data = verify_response.json()
    assert verified_user_data["email"] == TEST_EMAIL
    assert verified_user_data["is_active"] is True
    assert verified_user_data["is_verified"] is True

    # Verificar no BD que o usuário foi ativado e token removido
    await db_session.refresh(user)
    assert user.is_active is True
    assert user.is_verified is True
    assert user.verification_token_hash is None

    # 4. Tentar logar novamente (deve funcionar)
    login_response_after = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert login_response_after.status_code == 200
    assert "access_token" in login_response_after.json()


async def test_password_reset_flow(
    async_client: AsyncClient, db_session: AsyncSession, mock_email_service
):
    """Testa o fluxo completo de reset de senha."""
    _, mock_reset = mock_email_service

    # 1. Criar e ativar um usuário (usando a fixture do outro teste como base)
    reg_response = await async_client.post(
        "/api/v1/users/",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "full_name": "Reset User",
        },
    )
    user_id = reg_response.json()["id"]
    user = await db_session.get(User, user_id)
    user.is_active = True
    user.is_verified = True
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # 2. Solicitar reset de senha (deve enviar email mockado)
    forgot_response = await async_client.post(
        "/api/v1/auth/forgot-password", json={"email": TEST_EMAIL}
    )
    assert forgot_response.status_code == 202
    mock_reset.assert_called_once()  # Now this should work
    try:
        reset_token = mock_reset.call_args[1]["reset_token"]  # Pega o token do mock
    except (TypeError, KeyError, IndexError):
        pytest.fail("Could not retrieve reset_token from mocked email call")

    # Verificar no BD se o hash do token foi salvo
    await db_session.refresh(user)
    assert (
        user.reset_password_token_hash
        == hashlib.sha256(reset_token.encode("utf-8")).hexdigest()
    )
    assert user.reset_password_token_expires > datetime.now(timezone.utc).replace(
        tzinfo=None
    )

    # 3. Usar o token para definir nova senha
    reset_response = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": NEW_PASSWORD},
    )
    assert reset_response.status_code == 200
    reset_user_data = reset_response.json()
    assert reset_user_data["email"] == TEST_EMAIL

    # Verificar no BD se a senha mudou e o token foi removido
    await db_session.refresh(user)
    assert user.reset_password_token_hash is None
    # Verificar se a nova senha funciona (comparando hashes)
    # Precisamos do get_password_hash aqui, pois não temos a senha antiga
    assert user.hashed_password != get_password_hash(TEST_PASSWORD)  # Garante que mudou
    # Para verificar se a *nova* senha está correta, precisaríamos da `verify_password`
    # O teste de login abaixo faz essa verificação indiretamente.

    # 4. Tentar logar com a senha ANTIGA (deve falhar)
    old_login_response = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert old_login_response.status_code == 400
    assert "Incorrect email or password" in old_login_response.json()["detail"]

    # 5. Tentar logar com a senha NOVA (deve funcionar)
    new_login_response = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": NEW_PASSWORD}
    )
    assert new_login_response.status_code == 200
    assert "access_token" in new_login_response.json()
