# tests/test_06_oauth_google.py
import pytest
from sqlalchemy import select
from httpx import AsyncClient, Response
from sqlalchemy.ext.asyncio import AsyncSession
# Import monkeypatch directly if needed, although it's a pytest fixture
# from _pytest.monkeypatch import MonkeyPatch
import respx # For mocking HTTP requests
import urllib.parse # <-- ADICIONADO PARA URL ENCODE

from app.core.config import settings
from app.models.user import User
# Importar as constantes corretas DO MÓDULO ONDE SÃO DEFINIDAS
from app.api.endpoints.auth import GOOGLE_TOKEN_URL, GOOGLE_USERINFO_URL, GOOGLE_AUTH_URL

pytestmark = pytest.mark.asyncio

GOOGLE_TEST_EMAIL = "google.user@example.com"
GOOGLE_TEST_NAME = "Google User"
GOOGLE_AUTH_CODE = "valid_google_auth_code"
GOOGLE_INVALID_CODE = "invalid_google_auth_code"
GOOGLE_ACCESS_TOKEN = "valid_google_access_token"

# Configurações de teste (serão sobrescritas com monkeypatch onde necessário)
# Definir valores padrão robustos aqui pode ajudar
settings.GOOGLE_CLIENT_ID = "test_google_client_id_default"
settings.GOOGLE_CLIENT_SECRET = "test_google_client_secret_default"
settings.GOOGLE_REDIRECT_URI_FRONTEND = "http://default_frontend/google-callback"


@pytest.fixture(autouse=True)
def override_google_settings(monkeypatch):
    """Fixture to consistently override settings FOR ALL tests in this file."""
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_ID", "test_google_client_id_fixture")
    monkeypatch.setattr(settings, "GOOGLE_CLIENT_SECRET", "test_google_client_secret_fixture")
    # Define um padrão, mas pode ser sobrescrito DENTRO de um teste específico se necessário
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI_FRONTEND", "http://fixture_frontend/google-callback")

@pytest.mark.asyncio
async def test_get_google_login_url(async_client: AsyncClient, monkeypatch): # monkeypatch ainda é útil para sobrescrever o padrão da fixture
    """Testa a geração do URL de login do Google."""

    test_redirect_uri = "http://testfrontend/google-callback"
    monkeypatch.setattr(settings, "GOOGLE_REDIRECT_URI_FRONTEND", test_redirect_uri)

    response = await async_client.get("/api/v1/auth/google/login-url")
    assert response.status_code == 200
    data = response.json()
    assert "url" in data
    assert settings.GOOGLE_CLIENT_ID == "test_google_client_id_fixture"
    assert settings.GOOGLE_CLIENT_ID in data["url"]

    # --- CORREÇÃO: Encodar o redirect_uri antes de verificar ---
    encoded_redirect_uri = urllib.parse.quote(test_redirect_uri, safe="")
    assert encoded_redirect_uri in data["url"]
    # --- FIM CORREÇÃO ---

    assert "response_type=code" in data["url"]
    assert "scope=openid+email+profile" in data["url"]


@pytest.mark.asyncio
@respx.mock # respx precisa vir DEPOIS de pytest.mark.asyncio
async def test_google_callback_success_new_user(
    async_client: AsyncClient, db_session: AsyncSession, monkeypatch # Usar monkeypatch da fixture
):
    """Testa o callback do Google com sucesso para um novo usuário."""
    # Usar o redirect_uri definido na fixture 'override_google_settings'
    expected_redirect_uri = settings.GOOGLE_REDIRECT_URI_FRONTEND

    # 1. Mock a troca do código pelo token do Google
    route = respx.post(GOOGLE_TOKEN_URL).mock(
        return_value=Response(200, json={"access_token": GOOGLE_ACCESS_TOKEN, "token_type": "Bearer"})
    )
    # 2. Mock a busca de informações do usuário do Google
    route_userinfo = respx.get(GOOGLE_USERINFO_URL).mock( # Renomear variável para evitar conflito
        return_value=Response(200, json={
            "email": GOOGLE_TEST_EMAIL,
            "name": GOOGLE_TEST_NAME,
            "email_verified": True,
            "sub": "google_user_sub_123"
        })
    )

    # 3. Chamar o endpoint de callback da nossa API
    callback_response = await async_client.post(
        "/api/v1/auth/google/callback", json={"code": GOOGLE_AUTH_CODE}
    )

    # Verificar a resposta
    if callback_response.status_code != 200:
        print("Erro no callback (new user):", callback_response.json())
    assert callback_response.status_code == 200
    tokens = callback_response.json()
    assert "access_token" in tokens
    assert "refresh_token" in tokens

    # 4. Verificar se o usuário foi criado no BD
    user_result = await db_session.execute(
        select(User).where(User.email == GOOGLE_TEST_EMAIL)
    )
    db_user = user_result.scalars().first()
    assert db_user is not None
    assert db_user.full_name == GOOGLE_TEST_NAME
    assert db_user.is_active is True
    assert db_user.is_verified is True
    assert db_user.hashed_password is None

    # Verificar se as chamadas mockadas foram feitas
    assert route.called
    assert route_userinfo.called
    # Opcional: Verificar corpo da requisição POST (precisa decodificar urlencoded)
    # request_content = route.calls.last.request.content.decode()
    # parsed_content = urllib.parse.parse_qs(request_content)
    # assert parsed_content.get("redirect_uri") == [expected_redirect_uri]


# --- RESTANTE DO ARQUIVO test_06_oauth_google.py (sem alterações adicionais) ---
@pytest.mark.asyncio
@respx.mock
async def test_google_callback_success_existing_user(
    async_client: AsyncClient, db_session: AsyncSession, monkeypatch # Usar monkeypatch da fixture
):
    """Testa o callback do Google com sucesso para um usuário existente (criado via OAuth)."""
    expected_redirect_uri = settings.GOOGLE_REDIRECT_URI_FRONTEND

    # 1. Criar um usuário OAuth manualmente primeiro
    existing_user = User(
        email=GOOGLE_TEST_EMAIL,
        full_name="Original Name",
        is_active=True,
        is_verified=True,
        hashed_password=None
    )
    db_session.add(existing_user)
    await db_session.commit()
    await db_session.refresh(existing_user)
    original_id = existing_user.id

    # 2. Mock as chamadas do Google
    respx.post(GOOGLE_TOKEN_URL).mock(
        return_value=Response(200, json={"access_token": GOOGLE_ACCESS_TOKEN, "token_type": "Bearer"})
    )
    respx.get(GOOGLE_USERINFO_URL).mock(
        return_value=Response(200, json={
            "email": GOOGLE_TEST_EMAIL,
            "name": GOOGLE_TEST_NAME,
            "email_verified": True,
            "sub": "google_user_sub_123"
        })
    )

    # 3. Chamar o endpoint de callback
    callback_response = await async_client.post(
        "/api/v1/auth/google/callback", json={"code": GOOGLE_AUTH_CODE}
    )
    if callback_response.status_code != 200:
        print("Erro no callback (existing user):", callback_response.json())
    assert callback_response.status_code == 200
    tokens = callback_response.json()
    assert "access_token" in tokens

    # 4. Verificar se o usuário NO BD NÃO foi alterado
    user_after_result = await db_session.execute(select(User).where(User.id == original_id))
    user_after = user_after_result.scalars().first()
    assert user_after is not None
    assert user_after.full_name == "Original Name" # Nome não deve atualizar


@pytest.mark.asyncio
@respx.mock
async def test_google_callback_invalid_code(async_client: AsyncClient, monkeypatch): # Usar monkeypatch da fixture
    """Testa o callback do Google com um código inválido."""
    expected_redirect_uri = settings.GOOGLE_REDIRECT_URI_FRONTEND

    # Mock a troca do código para retornar erro
    respx.post(GOOGLE_TOKEN_URL).mock(
        return_value=Response(400, json={"error": "invalid_grant", "error_description": "Bad Request"})
    )

    # Chamar o endpoint de callback
    callback_response = await async_client.post(
        "/api/v1/auth/google/callback", json={"code": GOOGLE_INVALID_CODE}
    )
    assert callback_response.status_code == 400
    # A API deve retornar o erro específico da Google ou um genérico
    detail = callback_response.json().get("detail", "")
    assert "Código de autorização inválido ou expirado" in detail or "invalid_grant" in detail


@pytest.mark.asyncio
@respx.mock
async def test_google_callback_userinfo_error(async_client: AsyncClient, monkeypatch): # Usar monkeypatch da fixture
    """Testa o callback do Google com erro ao buscar userinfo."""
    expected_redirect_uri = settings.GOOGLE_REDIRECT_URI_FRONTEND

    # Mock a troca do código com sucesso
    respx.post(GOOGLE_TOKEN_URL).mock(
        return_value=Response(200, json={"access_token": GOOGLE_ACCESS_TOKEN, "token_type": "Bearer"})
    )
    # Mock a busca de userinfo para retornar erro
    respx.get(GOOGLE_USERINFO_URL).mock(
        return_value=Response(503, json={"error": "service_unavailable"}) # Simular erro 5xx
    )

    # Chamar o endpoint de callback
    callback_response = await async_client.post(
        "/api/v1/auth/google/callback", json={"code": GOOGLE_AUTH_CODE}
    )
    # A API deve capturar o erro HTTP do httpx e retornar 500
    assert callback_response.status_code == 500
    assert "Falha ao obter dados do utilizador" in callback_response.json()["detail"]


@pytest.mark.asyncio
@respx.mock
async def test_google_callback_email_not_verified(async_client: AsyncClient, monkeypatch): # Usar monkeypatch da fixture
    """Testa o callback do Google quando o email do Google não está verificado."""
    expected_redirect_uri = settings.GOOGLE_REDIRECT_URI_FRONTEND

    respx.post(GOOGLE_TOKEN_URL).mock(
        return_value=Response(200, json={"access_token": GOOGLE_ACCESS_TOKEN, "token_type": "Bearer"})
    )
    respx.get(GOOGLE_USERINFO_URL).mock(
        return_value=Response(200, json={
            "email": GOOGLE_TEST_EMAIL,
            "name": GOOGLE_TEST_NAME,
            "email_verified": False, # <-- Email não verificado
            "sub": "google_user_sub_123"
        })
    )

    callback_response = await async_client.post(
        "/api/v1/auth/google/callback", json={"code": GOOGLE_AUTH_CODE}
    )
    assert callback_response.status_code == 400
    assert "Email da Google não está verificado" in callback_response.json()["detail"]