# tests/test_10_auth_errors.py
import asyncio
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch, AsyncMock
import time
from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError # Para criar tokens inválidos

from app.models.user import User
from app.core import security
from app.crud.crud_user import user as crud_user
from app.schemas.user import UserCreate, UserUpdate # Importar UserUpdate
from app.api.endpoints.auth import create_mfa_challenge_token, MFA_CHALLENGE_SECRET_KEY, MFA_CHALLENGE_ALGORITHM
from app.core.config import settings
import pyotp

pytestmark = pytest.mark.asyncio

TEST_EMAIL = "autherror@example.com"
TEST_PASSWORD = "PasswordAuthError123!"
OTP_SECRET = security.generate_otp_secret() # Segredo conhecido para testes

@pytest.fixture
def mock_send_password_reset_email():
    """Mocka o serviço de email para reset de senha."""
    with patch("app.services.email_service.send_password_reset_email", new_callable=AsyncMock) as mock:
        mock.return_value = True  # Simula enfileiramento bem-sucedido
        yield mock

# Fixture parametrizada para criar usuário em diferentes estados
@pytest.fixture(scope="function")
async def setup_user_auth_error(db_session: AsyncSession, request) -> User:
    """Fixture to create a user, configurable state via markers."""
    params = request.param if hasattr(request, "param") else {}
    email = params.get("email", TEST_EMAIL)
    is_active = params.get("is_active", True)
    is_verified = params.get("is_verified", True)
    is_mfa_enabled = params.get("is_mfa_enabled", False)
    has_password = params.get("has_password", True)
    otp_secret_val = OTP_SECRET if is_mfa_enabled else None
    name = params.get("name", "Auth Error User")

    # Limpar usuário existente se houver
    existing_user = await crud_user.get_by_email(db_session, email=email)
    if existing_user:
        await crud_user.remove(db_session, id=existing_user.id)

    # Criar usuário
    user_in = UserCreate(email=email, password=TEST_PASSWORD if has_password else "DummyOAuthPass1!", full_name=name)
    user_obj, _ = await crud_user.create(db_session, obj_in=user_in)

    # Configurar estado desejado
    update_data = {
        "is_active": is_active,
        "is_verified": is_verified,
        "is_mfa_enabled": is_mfa_enabled,
        "otp_secret": otp_secret_val,
        "hashed_password": user_obj.hashed_password if has_password else None # Manter None para OAuth
    }
    user_obj = await crud_user.update(db_session, db_obj=user_obj, obj_in=update_data) # Usar update correto

    return user_obj

# --- Testes para /token ---

@pytest.mark.parametrize("setup_user_auth_error", [{"is_active": False, "is_verified": True}], indirect=True)
async def test_login_inactive_user(async_client: AsyncClient, setup_user_auth_error: User):
    """Testa login com usuário inativo."""
    response = await async_client.post("/api/v1/auth/token", data={
        "username": setup_user_auth_error.email, "password": TEST_PASSWORD
    })
    assert response.status_code == 400
    assert "Conta inativa ou e-mail não verificado" in response.json()["detail"]

@pytest.mark.parametrize("setup_user_auth_error", [{"is_active": True, "is_verified": False}], indirect=True)
async def test_login_unverified_user(async_client: AsyncClient, setup_user_auth_error: User):
    """Testa login com usuário não verificado."""
    response = await async_client.post("/api/v1/auth/token", data={
        "username": setup_user_auth_error.email, "password": TEST_PASSWORD
    })
    assert response.status_code == 400
    assert "Conta inativa ou e-mail não verificado" in response.json()["detail"]

@pytest.mark.parametrize("setup_user_auth_error", [{"has_password": False}], indirect=True)
async def test_login_oauth_user_with_password(async_client: AsyncClient, setup_user_auth_error: User):
    """Testa login com senha para usuário criado via OAuth (sem senha)."""
    response = await async_client.post("/api/v1/auth/token", data={
        "username": setup_user_auth_error.email, "password": "anypassword"
    })
    assert response.status_code == 400
    assert "Incorrect email or password" in response.json()["detail"] # A API retorna genérico aqui

# --- Testes para MFA ---

@pytest.mark.parametrize("setup_user_auth_error", [{"is_mfa_enabled": False}], indirect=True)
async def test_mfa_verify_when_not_enabled(async_client: AsyncClient, setup_user_auth_error: User):
    """Testa chamar /mfa/verify quando MFA não está ativo."""
    challenge_token = create_mfa_challenge_token(user_id=setup_user_auth_error.id)
    response = await async_client.post("/api/v1/auth/mfa/verify", json={
        "mfa_challenge_token": challenge_token, "otp_code": "123456"
    })
    assert response.status_code == 400 # API deve rejeitar
    assert "MFA não está (mais) habilitado" in response.json()["detail"]

@pytest.mark.parametrize("setup_user_auth_error", [{"is_mfa_enabled": True}], indirect=True)
async def test_mfa_verify_invalid_challenge_token(async_client: AsyncClient, setup_user_auth_error: User):
    """Testa /mfa/verify com challenge token inválido."""
    # 1. Token mal formado
    response = await async_client.post("/api/v1/auth/mfa/verify", json={
        "mfa_challenge_token": "invalid.token.string", "otp_code": "123456"
    })
    assert response.status_code == 400
    assert "inválido ou expirado" in response.json()["detail"]

    # 2. Token com assinatura errada (criar um com segredo diferente)
    wrong_secret_token = jwt.encode(
        {"sub": str(setup_user_auth_error.id), "exp": datetime.now(timezone.utc) + timedelta(minutes=5), "token_type": "mfa_challenge", "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE},
        "wrongsecret", algorithm=MFA_CHALLENGE_ALGORITHM
    )
    response = await async_client.post("/api/v1/auth/mfa/verify", json={
        "mfa_challenge_token": wrong_secret_token, "otp_code": "123456"
    })
    assert response.status_code == 400
    assert "inválido ou expirado" in response.json()["detail"]

    # 3. Token expirado
    # Criar token com expiração no passado manualmente
    past_exp = datetime.now(timezone.utc) - timedelta(minutes=1)
    expired_payload = {
        "sub": str(setup_user_auth_error.id),
        "exp": past_exp, # Expiração no passado
        "token_type": "mfa_challenge",
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": past_exp - timedelta(minutes=5) # iat antes da expiração
    }
    expired_token_manual = jwt.encode(expired_payload, MFA_CHALLENGE_SECRET_KEY, algorithm=MFA_CHALLENGE_ALGORITHM)
    response = await async_client.post("/api/v1/auth/mfa/verify", json={
        "mfa_challenge_token": expired_token_manual, "otp_code": "123456"
    })
    assert response.status_code == 400
    assert "inválido ou expirado" in response.json()["detail"]

@pytest.mark.parametrize("setup_user_auth_error", [{"is_mfa_enabled": True}], indirect=True)
async def test_mfa_verify_wrong_otp(async_client: AsyncClient, setup_user_auth_error: User):
    """Testa /mfa/verify com código OTP incorreto."""
    challenge_token = create_mfa_challenge_token(user_id=setup_user_auth_error.id)
    response = await async_client.post("/api/v1/auth/mfa/verify", json={
        "mfa_challenge_token": challenge_token, "otp_code": "000000" # Código errado
    })
    assert response.status_code == 400
    assert "Código OTP inválido" in response.json()["detail"]


# --- Testes para /refresh ---

@pytest.mark.asyncio
async def test_refresh_invalid_format(async_client: AsyncClient):
    """Testa /refresh com token em formato inválido."""
    response = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": "not.a.jwt"})
    assert response.status_code == 401
    assert "Could not validate credentials" in response.json()["detail"]

@pytest.mark.parametrize("setup_user_auth_error", [{}], indirect=True) # User comum
async def test_refresh_wrong_secret(async_client: AsyncClient, setup_user_auth_error: User):
    """Testa /refresh com token assinado com segredo errado."""
    user = setup_user_auth_error
    payload = {"sub": str(user.id), "exp": datetime.now(timezone.utc) + timedelta(minutes=10), "token_type": "refresh", "iss": settings.JWT_ISSUER}
    wrong_secret_token = jwt.encode(payload, "wrongsecret", algorithm=settings.ALGORITHM)
    response = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": wrong_secret_token})
    assert response.status_code == 401
    assert "Could not validate credentials" in response.json()["detail"]

# --- Testes para /forgot-password e /reset-password ---

@pytest.mark.asyncio
async def test_forgot_password_nonexistent_user(async_client: AsyncClient, mock_send_password_reset_email: AsyncMock):
    """Testa /forgot-password para email que não existe."""
    response = await async_client.post("/api/v1/auth/forgot-password", json={"email": "nonexistent@example.com"})
    assert response.status_code == 202 # Ainda retorna 202 por segurança
    mock_send_password_reset_email.assert_not_awaited() # Email não deve ser enviado

@pytest.mark.parametrize("setup_user_auth_error", [{"is_active": False}], indirect=True)
async def test_forgot_password_inactive_user(async_client: AsyncClient, setup_user_auth_error: User, mock_send_password_reset_email: AsyncMock):
    """Testa /forgot-password para usuário inativo."""
    response = await async_client.post("/api/v1/auth/forgot-password", json={"email": setup_user_auth_error.email})
    assert response.status_code == 202
    mock_send_password_reset_email.assert_not_awaited() # Email não deve ser enviado

@pytest.mark.parametrize("setup_user_auth_error", [{}], indirect=True)
async def test_reset_password_invalid_token_format(async_client: AsyncClient, setup_user_auth_error: User):
    """Testa /reset-password com token JWT mal formado."""
    response = await async_client.post("/api/v1/auth/reset-password", json={
        "token": "invalid.token.format", "new_password": "NewPassword123!"
    })
    assert response.status_code == 400
    assert "inválido ou expirado" in response.json()["detail"]

@pytest.mark.parametrize("setup_user_auth_error", [{}], indirect=True)
async def test_reset_password_wrong_secret(async_client: AsyncClient, setup_user_auth_error: User):
    """Testa /reset-password com token assinado com segredo errado."""
    payload = {"sub": setup_user_auth_error.email, "exp": datetime.now(timezone.utc) + timedelta(minutes=10), "token_type": "password_reset", "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE}
    wrong_secret_token = jwt.encode(payload, "wrongsecret", algorithm=settings.ALGORITHM)
    response = await async_client.post("/api/v1/auth/reset-password", json={
        "token": wrong_secret_token, "new_password": "NewPassword123!"
    })
    assert response.status_code == 400
    assert "inválido ou expirado" in response.json()["detail"]


# --- Testes para /verify-email ---

# --- CORREÇÃO (Removido o @pytest.mark.parametrize desnecessário) ---
async def test_verify_email_already_verified(async_client: AsyncClient, db_session: AsyncSession):
    """
    Testa que /verify-email falha com 400 se o token já foi usado
    (o que faz com que o usuário já esteja verificado).
    """
    # 1. Gerar um token de verificação válido
    user, token = await crud_user.create(db_session, obj_in=UserCreate(email="tempverify@example.com", password=TEST_PASSWORD))
    
    # 2. A primeira chamada deve funcionar (status 200)
    response1 = await async_client.get(f"/api/v1/auth/verify-email/{token}")
    assert response1.status_code == 200

    # 3. A segunda chamada com o MESMO token deve falhar (status 400)
    #    Porque o usuário agora está "is_verified=True" e o token foi "consumido" (apagado)
    response2 = await async_client.get(f"/api/v1/auth/verify-email/{token}")
    assert response2.status_code == 400
    assert "inválido ou expirado" in response2.json()["detail"]