# tests/test_02_email_flows.py
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch, MagicMock, AsyncMock # Manter AsyncMock
import hashlib
from datetime import datetime, timedelta, timezone

from app.models.user import User
from app.core import security

pytestmark = pytest.mark.asyncio

TEST_EMAIL = "emailflow@example.com"
TEST_PASSWORD = "PasswordFlow123!"
NEW_PASSWORD = "NewPasswordFlow456!"

# As fixtures separadas para mock são boas
@pytest.fixture()
def mock_send_verification_email():
    # Caminho completo da função a ser mockada
    with patch("app.api.endpoints.users.send_verification_email", new_callable=AsyncMock, return_value=True) as mock:
        yield mock

@pytest.fixture()
def mock_send_password_reset_email():
     # Caminho completo da função a ser mockada
    with patch("app.api.endpoints.auth.send_password_reset_email", new_callable=AsyncMock, return_value=True) as mock:
        yield mock


@pytest.mark.asyncio
async def test_email_verification_flow(
    async_client: AsyncClient,
    db_session: AsyncSession,
    mock_send_verification_email: AsyncMock # Usar a fixture correta
):
    """Test full email verification flow: register -> verify."""
    # 1. Register User (deve chamar o mock)
    response_register = await async_client.post(
        "/api/v1/users/",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": "Email Flow User"},
    )
    assert response_register.status_code == 201
    user_data = response_register.json()
    user_id = user_data["id"]

    # Dar tempo para BackgroundTasks (geralmente não necessário com AsyncMock, mas pode ajudar em alguns casos)
    # await asyncio.sleep(0.01)

    # Verificar se o mock foi chamado (awaited)
    mock_send_verification_email.assert_awaited_once() # Deve funcionar agora
    call_args, call_kwargs = mock_send_verification_email.await_args
    assert call_kwargs.get('email_to') == TEST_EMAIL
    assert "verification_token" in call_kwargs
    verification_token = call_kwargs["verification_token"]
    assert verification_token is not None

    # Verificar estado do usuário no BD
    user = await db_session.get(User, user_id)
    assert user is not None
    assert user.is_active is False
    assert user.is_verified is False
    assert user.verification_token_hash == hashlib.sha256(verification_token.encode('utf-8')).hexdigest()

    # 2. Verificar Email com o token
    response_verify = await async_client.get(f"/api/v1/auth/verify-email/{verification_token}")
    assert response_verify.status_code == 200

    # Verificar estado do usuário no BD após verificação
    await db_session.refresh(user)
    assert user.is_active is True
    assert user.is_verified is True
    assert user.verification_token_hash is None

    # 3. Tentar verificar novamente (deve falhar)
    response_verify_again = await async_client.get(f"/api/v1/auth/verify-email/{verification_token}")
    assert response_verify_again.status_code == 400

    # 4. Tentar verificar com token inválido
    response_verify_invalid = await async_client.get("/api/v1/auth/verify-email/invalidtoken")
    assert response_verify_invalid.status_code == 400


@pytest.mark.asyncio
async def test_password_reset_flow(
    async_client: AsyncClient,
    db_session: AsyncSession,
    mock_send_password_reset_email: AsyncMock # Usar a fixture correta
):
    """Test full password reset flow: request reset -> reset password."""
    # 1. Registrar e Ativar Usuário
    response_register = await async_client.post(
        "/api/v1/users/",
        json={"email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": "Reset Flow User"},
    )
    assert response_register.status_code == 201
    user_id = response_register.json()["id"]
    user = await db_session.get(User, user_id)
    assert user is not None
    user.is_active = True
    user.is_verified = True
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # 2. Solicitar Reset de Senha (deve chamar o mock)
    response_forgot = await async_client.post("/api/v1/auth/forgot-password", json={"email": TEST_EMAIL})
    assert response_forgot.status_code == 202

    # await asyncio.sleep(0.01) # Pode ajudar se o mock não for chamado

    # Verificar se o mock foi chamado (awaited)
    mock_send_password_reset_email.assert_awaited_once() # Deve funcionar agora
    call_args, call_kwargs = mock_send_password_reset_email.await_args
    assert call_kwargs.get('email_to') == TEST_EMAIL
    assert "reset_token" in call_kwargs
    reset_token = call_kwargs["reset_token"]
    assert reset_token is not None

    # Verificar estado do usuário no BD
    await db_session.refresh(user)
    assert user.reset_password_token_hash == hashlib.sha256(reset_token.encode('utf-8')).hexdigest()

    # 3. Resetar Senha com o token
    response_reset = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": NEW_PASSWORD},
    )
    assert response_reset.status_code == 200

    # Verificar estado do usuário no BD após reset
    await db_session.refresh(user)
    assert user.reset_password_token_hash is None
    assert security.verify_password(NEW_PASSWORD, user.hashed_password) is True

    # 4. Tentar logar com senha antiga (falha)
    login_old_response = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert login_old_response.status_code == 400

    # 5. Tentar logar com senha nova (sucesso)
    login_new_response = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": NEW_PASSWORD}
    )
    assert login_new_response.status_code == 200

    # 6. Tentar resetar de novo com mesmo token (falha)
    response_reset_again = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": reset_token, "new_password": "AnotherPassword123!"},
    )
    assert response_reset_again.status_code == 400

    # 7. Tentar resetar com token inválido
    response_reset_invalid = await async_client.post(
        "/api/v1/auth/reset-password",
        json={"token": "invalidtoken", "new_password": "AnotherPassword123!"},
    )
    assert response_reset_invalid.status_code == 400