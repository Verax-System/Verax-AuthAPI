# tests/test_02_coverage_increase.py
import pytest
import respx
from httpx import (
    AsyncClient, Response, Request, HTTPStatusError, ConnectError, ReadTimeout
)
from sqlalchemy.ext.asyncio import AsyncSession
# CORREÇÃO: Importar AsyncMock de unittest.mock se estiver usando Python >= 3.8
# Se Python < 3.8, instale 'asyncmock' e importe de lá
from unittest.mock import patch, AsyncMock
from datetime import datetime, timedelta, timezone
from fastapi import status, HTTPException
from sqlalchemy.exc import IntegrityError

from app.crud import crud_refresh_token, crud_mfa_recovery_code
from app.models.user import User
from app.crud.crud_user import user as crud_user
from app.schemas.user import UserCreate
from app.core import security
from app.core.config import settings
from app.api.endpoints.auth import GOOGLE_TOKEN_URL, GOOGLE_USERINFO_URL
from app.db import session as db_session_module

# Marcar todos os testes como asyncio
pytestmark = pytest.mark.asyncio

# --- CONSTANTES DE TESTE ---
TEST_EMAIL_COV = "coverage@example.com"
TEST_PASSWORD_COV = "CoveragePass123!"
TEST_EMAIL_ADMIN = "admin_cov@example.com"
TEST_PASSWORD_ADMIN = "AdminPass123!"
TEST_GOOGLE_CODE = "valid_google_code"

# --- FIXTURES ---

@pytest.fixture(scope="function", autouse=True)
async def clear_users(db_session: AsyncSession):
    """Limpa usuários de teste antes de cada teste para evitar conflitos."""
    yield # Executa o teste
    # Limpeza já é feita pelo conftest, mas deixamos aqui caso precise no futuro
    pass

@pytest.fixture(scope="function")
async def active_user_cov(async_client: AsyncClient, db_session: AsyncSession) -> User:
    """Fixture que cria um usuário NÃO-ADMIN, ativo e verificado."""
    user = await crud_user.get_by_email(db_session, email=TEST_EMAIL_COV)
    if user:
         await db_session.delete(user)
         await db_session.commit()

    user_in = UserCreate(email=TEST_EMAIL_COV, password=TEST_PASSWORD_COV, full_name="Coverage User")
    user_obj, _ = await crud_user.create(db_session, obj_in=user_in)

    user_obj.is_active = True
    user_obj.is_verified = True
    user_obj.custom_claims = {"roles": ["user"]} # Definir como não-admin
    db_session.add(user_obj)
    await db_session.commit()
    await db_session.refresh(user_obj)
    return user_obj

@pytest.fixture(scope="function")
async def admin_user_token(async_client: AsyncClient, db_session: AsyncSession) -> str:
    """Fixture que cria um usuário ADMIN ativo e retorna seu token de acesso."""
    user = await crud_user.get_by_email(db_session, email=TEST_EMAIL_ADMIN)
    if user:
         await db_session.delete(user)
         await db_session.commit()

    user_in = UserCreate(email=TEST_EMAIL_ADMIN, password=TEST_PASSWORD_ADMIN, full_name="Admin Coverage")
    user_obj, _ = await crud_user.create(db_session, obj_in=user_in)

    user_obj.is_active = True
    user_obj.is_verified = True
    user_obj.custom_claims = {"roles": ["admin"]} # Definir como admin
    db_session.add(user_obj)
    await db_session.commit()

    login_resp = await async_client.post("/api/v1/auth/token", data={
        "username": TEST_EMAIL_ADMIN,
        "password": TEST_PASSWORD_ADMIN
    })
    assert login_resp.status_code == 200, f"Falha ao logar admin: {login_resp.text}"
    return login_resp.json()["access_token"]


@pytest.fixture(scope="function")
async def non_admin_user_token(async_client: AsyncClient, active_user_cov: User) -> str:
    """Fixture que retorna um token de acesso para o usuário NÃO-ADMIN."""
    login_response = await async_client.post("/api/v1/auth/token", data={
        "username": active_user_cov.email,
        "password": TEST_PASSWORD_COV
    })
    assert login_response.status_code == 200, f"Falha ao logar user cov: {login_response.text}"
    return login_response.json()["access_token"]


# --- TESTES DE GOOGLE OAUTH (httpx Mocks) ---
# (Mantendo seus testes respx como estão)
@pytest.mark.asyncio
@respx.mock
async def test_google_callback_invalid_code(respx_mock, async_client: AsyncClient):
    respx_mock.post(GOOGLE_TOKEN_URL).mock(return_value=Response(
        status_code=400,
        json={"error": "invalid_grant", "error_description": "Bad Request"}
    ))
    response = await async_client.post("/api/v1/auth/google/callback", json={"code": "invalid_google_code"})
    assert response.status_code == 400
    assert "Código de autorização inválido ou expirado" in response.json()["detail"]

@pytest.mark.asyncio
@respx.mock
async def test_google_callback_network_error_token_exchange(respx_mock, async_client: AsyncClient):
    respx_mock.post(GOOGLE_TOKEN_URL).mock(side_effect=ConnectError("Connection failed"))
    response = await async_client.post("/api/v1/auth/google/callback", json={"code": TEST_GOOGLE_CODE})
    assert response.status_code == 500
    assert "Erro ao contactar serviço de login" in response.json()["detail"]

@pytest.mark.asyncio
@respx.mock
async def test_google_callback_no_access_token_in_response(respx_mock, async_client: AsyncClient):
    respx_mock.post(GOOGLE_TOKEN_URL).mock(return_value=Response(
        status_code=200,
        json={"id_token": "some_id_token"} # Missing access_token
    ))
    response = await async_client.post("/api/v1/auth/google/callback", json={"code": TEST_GOOGLE_CODE})
    assert response.status_code == 500
    assert "Falha ao obter token da Google" in response.json()["detail"]

@pytest.mark.asyncio
@respx.mock
async def test_google_callback_network_error_userinfo(respx_mock, async_client: AsyncClient):
    google_access_token = "valid_google_access_token"
    respx_mock.post(GOOGLE_TOKEN_URL).mock(return_value=Response(
        status_code=200, json={"access_token": google_access_token}
    ))
    respx_mock.get(GOOGLE_USERINFO_URL).mock(side_effect=ReadTimeout("Timeout occurred"))
    response = await async_client.post("/api/v1/auth/google/callback", json={"code": TEST_GOOGLE_CODE})
    assert response.status_code == 500
    assert "Falha ao obter dados do utilizador" in response.json()["detail"]

@pytest.mark.asyncio
@respx.mock
async def test_google_callback_userinfo_no_email(respx_mock, async_client: AsyncClient):
    google_access_token = "valid_google_access_token"
    respx_mock.post(GOOGLE_TOKEN_URL).mock(return_value=Response(
        status_code=200, json={"access_token": google_access_token}
    ))
    respx_mock.get(GOOGLE_USERINFO_URL).mock(return_value=Response(
        status_code=200, json={"sub": "123", "name": "Test User", "email_verified": True}
    ))
    response = await async_client.post("/api/v1/auth/google/callback", json={"code": TEST_GOOGLE_CODE})
    assert response.status_code == 400
    assert "Email não retornado pela Google" in response.json()["detail"]

@pytest.mark.asyncio
@respx.mock
async def test_google_callback_userinfo_email_not_verified(respx_mock, async_client: AsyncClient):
    google_access_token = "valid_google_access_token"
    respx_mock.post(GOOGLE_TOKEN_URL).mock(return_value=Response(
        status_code=200, json={"access_token": google_access_token}
    ))
    respx_mock.get(GOOGLE_USERINFO_URL).mock(return_value=Response(
        status_code=200, json={"sub": "123", "name": "Test User", "email": "test@gmail.com", "email_verified": False}
    ))
    response = await async_client.post("/api/v1/auth/google/callback", json={"code": TEST_GOOGLE_CODE})
    assert response.status_code == 400
    assert "Email da Google não está verificado" in response.json()["detail"]

@pytest.mark.asyncio
@respx.mock
async def test_google_callback_crud_error(respx_mock, async_client: AsyncClient, db_session: AsyncSession):
    google_access_token = "valid_google_access_token"
    user_info = {"sub": "123", "name": "Test User", "email": "cruderror@gmail.com", "email_verified": True}

    respx_mock.post(GOOGLE_TOKEN_URL).mock(return_value=Response(200, json={"access_token": google_access_token}))
    respx_mock.get(GOOGLE_USERINFO_URL).mock(return_value=Response(200, json=user_info))

    with patch("app.crud.crud_user.user.get_or_create_by_email_oauth", new_callable=AsyncMock) as mock_get_or_create:
        mock_get_or_create.side_effect = Exception("Database error")
        response = await async_client.post("/api/v1/auth/google/callback", json={"code": TEST_GOOGLE_CODE})
        assert response.status_code == 500
        assert "Erro interno ao processar conta" in response.json()["detail"]

@pytest.mark.asyncio
async def test_get_google_login_url(async_client: AsyncClient):
    """Testa o endpoint /google/login-url."""
    response = await async_client.get("/api/v1/auth/google/login-url")
    assert response.status_code == 200
    data = response.json()
    assert "url" in data
    assert "https://accounts.google.com/o/oauth2/v2/auth" in data["url"]
    assert "client_id=" in data["url"]
    assert "redirect_uri=" in data["url"]
    assert "scope=openid+email+profile" in data["url"]

# --- TESTES DE LÓGICA DE CRUD E SERVIÇO ---

@pytest.mark.asyncio
async def test_crud_refresh_token_create_integrity_error(
    db_session: AsyncSession,
    active_user_cov: User,
    mocker # Requer pytest-mock
):
    """Testa se o HTTPException 409 é levantado em caso de IntegrityError."""
    user = active_user_cov

    mocker.patch.object(db_session, "commit", new_callable=AsyncMock,
                        side_effect=IntegrityError("Mocked Integrity Error", params=None, orig=None))
    mocker.patch.object(db_session, "rollback", new_callable=AsyncMock)

    with pytest.raises(HTTPException) as exc_info:
        await crud_refresh_token.create_refresh_token(
            db=db_session,
            user=user,
            token="test-token-integrity",
            expires_at=datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(days=1)
        )

    assert exc_info.value.status_code == 409
    assert "Failed to create token due to conflict" in exc_info.value.detail

@pytest.mark.asyncio
async def test_reset_password_token_used_or_invalid_in_db(async_client: AsyncClient, active_user_cov: User, db_session: AsyncSession):
    user = active_user_cov
    _, reset_token = await crud_user.generate_password_reset_token(db=db_session, user=user)

    # Invalidar token no DB
    user.reset_password_token_hash = None
    user.reset_password_token_expires = None
    db_session.add(user)
    await db_session.commit()

    response = await async_client.post("/api/v1/auth/reset-password", json={
        "token": reset_token, "new_password": "NewPassword456!"
    })
    assert response.status_code == 400
    assert "inválido, expirado ou já utilizado (DB)" in response.json()["detail"]

@pytest.mark.asyncio
async def test_crud_get_or_create_oauth_existing_user_no_name(db_session: AsyncSession):
    email = "oauth_existing@example.com"
    existing = await crud_user.get_by_email(db_session, email=email)
    if existing:
        await db_session.delete(existing)
        await db_session.commit()

    user_in = UserCreate(email=email, password=TEST_PASSWORD_COV, full_name=None)
    user_obj, _ = await crud_user.create(db_session, obj_in=user_in)
    assert user_obj.full_name is None

    new_name = "OAuth User Name"
    result_user = await crud_user.get_or_create_by_email_oauth(db=db_session, email=email, full_name=new_name)

    assert result_user.id == user_obj.id
    assert result_user.full_name == new_name
    await db_session.refresh(user_obj) # Reload user_obj from DB to check update
    assert user_obj.full_name == new_name

@pytest.mark.asyncio
async def test_crud_set_pending_otp_secret_value_error(db_session: AsyncSession, active_user_cov: User):
    user = active_user_cov
    user.is_mfa_enabled = True
    db_session.add(user)
    await db_session.commit()

    with pytest.raises(ValueError, match="MFA já está habilitado."):
        await crud_user.set_pending_otp_secret(db=db_session, user=user, otp_secret="new_secret")

@pytest.mark.asyncio
async def test_crud_confirm_mfa_enable_already_enabled(db_session: AsyncSession, active_user_cov: User):
    user = active_user_cov
    user.is_mfa_enabled = True
    user.otp_secret = "some_secret"
    db_session.add(user)
    await db_session.commit()
    result = await crud_user.confirm_mfa_enable(db=db_session, user=user, otp_code="123456")
    assert result is None

@pytest.mark.asyncio
async def test_crud_confirm_mfa_enable_no_pending_secret(db_session: AsyncSession, active_user_cov: User):
    user = active_user_cov
    user.otp_secret = None
    user.is_mfa_enabled = False
    db_session.add(user)
    await db_session.commit()
    result = await crud_user.confirm_mfa_enable(db=db_session, user=user, otp_code="123456")
    assert result is None

@pytest.mark.asyncio
async def test_get_async_engine_no_db_url(monkeypatch):
    """Testa se a criação da engine falha se a DATABASE_URL não estiver definida."""
    original_engine = db_session_module._async_engine
    was_defined = hasattr(settings, "DATABASE_URL")

    # Garante que a engine será recriada
    db_session_module._async_engine = None

    # Remover o atributo se ele existir
    if was_defined:
        monkeypatch.delattr(settings, "DATABASE_URL", raising=False)

    try:
        # Tenta criar a engine, esperando o RuntimeError
        with pytest.raises(RuntimeError) as excinfo:
            db_session_module.get_async_engine()

        # Verifica a mensagem dentro do RuntimeError
        assert "DATABASE_URL not loaded" in str(excinfo.value) or "não definida" in str(excinfo.value)

    finally:
        # CORREÇÃO: Remover restauração manual, monkeypatch faz isso automaticamente
        db_session_module._async_engine = original_engine
        # Reset engine again para garantir isolamento
        db_session_module._async_engine = None

@pytest.mark.asyncio
async def test_crud_base_remove_not_found(db_session: AsyncSession):
    result = await crud_user.remove(db=db_session, id=99999)
    assert result is None

@pytest.mark.asyncio
async def test_crud_mfa_get_valid_recovery_code_not_found(db_session: AsyncSession, active_user_cov: User):
    user = active_user_cov
    await crud_mfa_recovery_code.create_recovery_codes(db=db_session, user=user)
    result_code = await crud_mfa_recovery_code.get_valid_recovery_code(
        db=db_session, user=user, plain_code="invalid-code-format"
    )
    assert result_code is None

@pytest.mark.asyncio
async def test_crud_mfa_get_valid_recovery_code_already_used(db_session: AsyncSession, active_user_cov: User):
    user = active_user_cov
    plain_codes = await crud_mfa_recovery_code.create_recovery_codes(db=db_session, user=user)
    code_to_use = plain_codes[0]
    db_code = await crud_mfa_recovery_code.get_valid_recovery_code(
        db=db_session, user=user, plain_code=code_to_use
    )
    assert db_code is not None
    await crud_mfa_recovery_code.mark_code_as_used(db=db_session, db_code=db_code)
    result_code_again = await crud_mfa_recovery_code.get_valid_recovery_code(
        db=db_session, user=user, plain_code=code_to_use
    )
    assert result_code_again is None

@pytest.mark.asyncio
async def test_crud_user_disable_mfa_not_enabled(db_session: AsyncSession, active_user_cov: User):
    user = active_user_cov
    user.is_mfa_enabled = False
    user.otp_secret = None
    db_session.add(user)
    await db_session.commit()

    updated_user = await crud_user.disable_mfa(db=db_session, user=user, otp_code="123456")
    assert updated_user is not None
    assert updated_user.id == user.id
    assert updated_user.is_mfa_enabled is False

@pytest.mark.asyncio
async def test_crud_user_disable_mfa_invalid_otp(db_session: AsyncSession, active_user_cov: User):
    user = active_user_cov
    user.is_mfa_enabled = True
    user.otp_secret = security.generate_otp_secret()
    db_session.add(user)
    await db_session.commit()

    result_user = await crud_user.disable_mfa(db=db_session, user=user, otp_code="000000")
    assert result_user is None

@pytest.mark.asyncio
async def test_crud_base_update_with_dict(db_session: AsyncSession, active_user_cov: User):
    user = active_user_cov
    new_name = "Updated Name Via Dict"
    update_data = {"full_name": new_name, "is_active": False}

    updated_user = await crud_user.update(db=db_session, db_obj=user, obj_in=update_data)

    assert updated_user is not None
    assert updated_user.id == user.id
    assert updated_user.full_name == new_name
    assert updated_user.is_active is False
    await db_session.refresh(user)
    assert user.full_name == new_name
    assert user.is_active is False

# --- TESTES DE ENDPOINT (RBAC, MGMT, AUTH) ---

@pytest.mark.asyncio
async def test_mgmt_update_claims_user_not_found_by_id(async_client: AsyncClient, admin_user_token: str):
    api_key = settings.INTERNAL_API_KEY
    headers = {"X-API-Key": api_key}
    response = await async_client.patch("/api/v1/mgmt/users/99999/claims", headers=headers, json={"roles": ["test"]})
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Usuário não encontrado" in response.json()["detail"]

@pytest.mark.asyncio
async def test_mgmt_update_claims_user_not_found_by_email(async_client: AsyncClient, admin_user_token: str):
    api_key = settings.INTERNAL_API_KEY
    headers = {"X-API-Key": api_key}
    response = await async_client.patch("/api/v1/mgmt/users/nonexistent@user.com/claims", headers=headers, json={"roles": ["test"]})
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Usuário não encontrado" in response.json()["detail"]

@pytest.mark.asyncio
async def test_mgmt_update_claims_invalid_identifier(async_client: AsyncClient, admin_user_token: str):
    api_key = settings.INTERNAL_API_KEY
    headers = {"X-API-Key": api_key}
    response = await async_client.patch("/api/v1/mgmt/users/invalid-identifier/claims", headers=headers, json={"roles": ["test"]})
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "Usuário não encontrado" in response.json()["detail"]

@pytest.mark.asyncio
async def test_users_read_users_forbidden(async_client: AsyncClient, non_admin_user_token: str):
    headers = {"Authorization": f"Bearer {non_admin_user_token}"}
    response = await async_client.get("/api/v1/users/", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Requer privilégios de administrador" in response.json()["detail"]

@pytest.mark.asyncio
async def test_users_read_user_by_id_forbidden(async_client: AsyncClient, non_admin_user_token: str, active_user_cov: User):
    headers = {"Authorization": f"Bearer {non_admin_user_token}"}
    response = await async_client.get(f"/api/v1/users/{active_user_cov.id}", headers=headers)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert "Requer privilégios de administrador" in response.json()["detail"]

@pytest.mark.asyncio
async def test_users_read_user_by_id_not_found_as_admin(async_client: AsyncClient, admin_user_token: str):
    headers = {"Authorization": f"Bearer {admin_user_token}"}
    response = await async_client.get("/api/v1/users/99999", headers=headers)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert "User not found" in response.json()["detail"]

@pytest.mark.asyncio
async def test_admin_can_read_users(async_client: AsyncClient, admin_user_token: str):
    headers = {"Authorization": f"Bearer {admin_user_token}"}
    response = await async_client.get("/api/v1/users/", headers=headers)
    assert response.status_code == 200
    assert len(response.json()) > 0

@pytest.mark.asyncio
async def test_full_password_reset_flow(
    async_client: AsyncClient,
    db_session: AsyncSession,
    active_user_cov: User,
    mocker # Requer pytest-mock
):
    user = active_user_cov
    mock_send_email = mocker.patch("app.api.endpoints.auth.send_password_reset_email", return_value=True)

    response_forgot = await async_client.post("/api/v1/auth/forgot-password", json={"email": user.email})
    assert response_forgot.status_code == 202
    mock_send_email.assert_called_once()

    await db_session.refresh(user)
    assert user.reset_password_token_hash is not None
    call_args = mock_send_email.call_args
    reset_token = call_args[1].get('reset_token')
    assert reset_token is not None

    NEW_PASSWORD = "NewPassword456!"
    response_reset = await async_client.post("/api/v1/auth/reset-password", json={"token": reset_token, "new_password": NEW_PASSWORD})
    assert response_reset.status_code == 200
    assert response_reset.json()["email"] == user.email

    await db_session.refresh(user)
    assert user.reset_password_token_hash is None

    response_old_login = await async_client.post("/api/v1/auth/token", data={"username": user.email, "password": TEST_PASSWORD_COV})
    assert response_old_login.status_code == 400

    response_new_login = await async_client.post("/api/v1/auth/token", data={"username": user.email, "password": NEW_PASSWORD})
    assert response_new_login.status_code == 200
    assert "access_token" in response_new_login.json()


@pytest.mark.asyncio
async def test_refresh_and_logout_flow(
    async_client: AsyncClient,
    db_session: AsyncSession,
    active_user_cov: User
):
    user = active_user_cov

    login_resp = await async_client.post("/api/v1/auth/token", data={"username": user.email, "password": TEST_PASSWORD_COV})
    assert login_resp.status_code == 200
    data = login_resp.json()
    access_token_1 = data["access_token"]
    refresh_token_1 = data["refresh_token"]

    # Verificar se o token existe e é válido ANTES do refresh
    db_token_before = await crud_refresh_token.get_refresh_token(db=db_session, token=refresh_token_1)
    assert db_token_before is not None
    assert db_token_before.is_revoked is False

    # Chamar refresh - ESSA CHAMADA DEVE INVALIDAR refresh_token_1 NO SEU CÓDIGO DE PRODUÇÃO
    refresh_resp = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token_1})
    assert refresh_resp.status_code == 200, f"Refresh falhou: {refresh_resp.text}"
    data_2 = refresh_resp.json()
    access_token_2 = data_2["access_token"]
    refresh_token_2 = data_2["refresh_token"]

    # --- VERIFICAÇÃO CORRETA ---
    # Limpa o cache da sessão para garantir leitura fresca do banco
    db_session.expire_all()
    # Verifica se o token antigo NÃO É MAIS VÁLIDO usando a função get_refresh_token
    # (Esta função já filtra tokens revogados, expirados ou deletados)
    db_token_after_old = await crud_refresh_token.get_refresh_token(db=db_session, token=refresh_token_1)

    # ESTA É A LINHA QUE ESTÁ FALHANDO DEVIDO À LÓGICA DA SUA APLICAÇÃO
    assert db_token_after_old is None, f"Token antigo (hash starting {refresh_token_1[:10]}...) ainda foi encontrado como válido após refresh. Verifique a lógica de revogação/deleção no endpoint /refresh e no crud create_refresh_token."

    # Verificar novo token
    db_session.expire_all()
    db_token_after_new = await crud_refresh_token.get_refresh_token(db=db_session, token=refresh_token_2)
    assert db_token_after_new is not None
    assert db_token_after_new.is_revoked is False

    # Verificar rotação
    assert access_token_1 != access_token_2
    assert refresh_token_1 != refresh_token_2

    # Tentar usar token antigo (deve falhar porque não é mais válido)
    refresh_resp_old = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token_1})
    assert refresh_resp_old.status_code == 401

    # Chamar logout com novo token
    logout_resp = await async_client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token_2})
    assert logout_resp.status_code == 204

    # Verificar se o token do logout foi revogado (get_refresh_token filtra revogados)
    db_session.expire_all()
    db_token_after_logout = await crud_refresh_token.get_refresh_token(db=db_session, token=refresh_token_2)
    assert db_token_after_logout is None

    # Tentar usar token pós-logout
    refresh_resp_logged_out = await async_client.post("/api/v1/auth/logout", json={"refresh_token": refresh_token_2})
    # Após logout, tentar usar o token para logout novamente deve falhar ou não fazer nada
    # Verificar se o token ainda é inválido para refresh
    refresh_after_logout = await async_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token_2})
    assert refresh_after_logout.status_code == 401

    