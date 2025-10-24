# tests/test_13_dependencies.py
import pytest
from fastapi import HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import MagicMock, AsyncMock, patch  # <-- ADICIONADO 'patch'

# --- ADICIONADO (Imports ausentes) ---
import time
from jose import jwt
from datetime import datetime, timedelta, timezone # Embora 'time' seja usado, 'datetime' é melhor para JWT
# --- FIM ADIÇÃO ---

from app.api import dependencies
from app.models.user import User
from app.core import security
from app.core.config import settings

pytestmark = pytest.mark.asyncio

@pytest.fixture
def mock_db_session():
    """Fixture for a mock AsyncSession."""
    return AsyncMock(spec=AsyncSession)

@pytest.fixture
def mock_crud_get():
    """Fixture to mock crud_user.get."""
    # 'patch' aqui estava causando NameError
    with patch("app.crud.crud_user.user.get", new_callable=AsyncMock) as mock:
        yield mock

# --- Testes para get_current_user_from_token ---

async def test_get_current_user_valid_token(mock_db_session, mock_crud_get):
    """Test getting user with a valid bearer token."""
    user_id = 1
    user_email = "depuser@example.com"
    user_obj = User(id=user_id, email=user_email, is_active=True, is_verified=True, is_mfa_enabled=False) # Adicionar campos
    mock_crud_get.return_value = user_obj

    # Criar um token de acesso válido manualmente
    # --- CORREÇÃO (create_access_token retorna str, não tupla) ---
    access_token = security.create_access_token(user=user_obj)
    # --- FIM CORREÇÃO ---
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=access_token)

    # Chamar a dependência diretamente
    result_user = await dependencies.get_current_user_from_token(db=mock_db_session, creds=creds)

    mock_crud_get.assert_awaited_once_with(mock_db_session, id=user_id)
    assert result_user == user_obj

async def test_get_current_user_invalid_scheme(mock_db_session):
    """Test getting user with invalid authorization scheme."""
    creds = HTTPAuthorizationCredentials(scheme="Basic", credentials="somecreds")
    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_current_user_from_token(db=mock_db_session, creds=creds)
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Esquema de autorização inválido" in excinfo.value.detail

async def test_get_current_user_invalid_token(mock_db_session):
    """Test getting user with an invalid/malformed token."""
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid.token")
    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_current_user_from_token(db=mock_db_session, creds=creds)
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Could not validate credentials" in excinfo.value.detail

async def test_get_current_user_no_sub(mock_db_session):
    """Test getting user with a token missing the 'sub' claim."""
    # Criar token sem 'sub'
    expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    payload = {"exp": expires, "token_type": "access", "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE}
    token_no_sub = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token_no_sub)
    
    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_current_user_from_token(db=mock_db_session, creds=creds)
    
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    # A verificação de 'sub' é feita após o decode
    assert "Could not validate credentials" in excinfo.value.detail

async def test_get_current_user_not_found_in_db(mock_db_session, mock_crud_get):
    """Test getting user when user ID from token is not found in DB."""
    user_id = 999
    mock_crud_get.return_value = None  # Simular usuário não encontrado

    # Criar token válido para user ID 999
    expires = datetime.now(timezone.utc) + timedelta(minutes=10)
    token_payload = {"sub": str(user_id), "email": "a@b.com", "exp": expires, "token_type": "access", "iss": settings.JWT_ISSUER, "aud": settings.JWT_AUDIENCE}
    valid_token_for_nonexistent_user = jwt.encode(token_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials=valid_token_for_nonexistent_user)

    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_current_user_from_token(db=mock_db_session, creds=creds)
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "Could not validate credentials" in excinfo.value.detail
    mock_crud_get.assert_awaited_once_with(mock_db_session, id=user_id)


# --- Testes para get_current_active_user ---

async def test_get_current_active_user_inactive():
    """Test dependency raises error for inactive user."""
    inactive_user = User(id=1, email="inactive@example.com", is_active=False)
    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_current_active_user(current_user=inactive_user)
    assert excinfo.value.status_code == 400
    assert "Inactive user" in excinfo.value.detail


# --- Testes para get_current_admin_user ---

async def test_get_current_admin_user_success():
    """Test admin dependency success for admin user."""
    admin_user = User(id=1, email="admin@example.com", is_active=True, custom_claims={"roles": ["admin", "user"]})
    result = await dependencies.get_current_admin_user(current_user=admin_user)
    assert result == admin_user

async def test_get_current_admin_user_no_claims():
    """Test admin dependency failure when custom_claims is None."""
    user_no_claims = User(id=2, email="noclaims@example.com", is_active=True, custom_claims=None)
    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_current_admin_user(current_user=user_no_claims)
    assert excinfo.value.status_code == status.HTTP_403_FORBIDDEN
    assert "Não autorizado" in excinfo.value.detail

async def test_get_current_admin_user_no_roles():
    """Test admin dependency failure when 'roles' key is missing."""
    user_no_roles = User(id=3, email="noroles@example.com", is_active=True, custom_claims={"permissions": ["read"]})
    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_current_admin_user(current_user=user_no_roles)
    assert excinfo.value.status_code == status.HTTP_403_FORBIDDEN

async def test_get_current_admin_user_not_admin_role():
    """Test admin dependency failure when 'admin' is not in roles list."""
    user_not_admin = User(id=4, email="notadmin@example.com", is_active=True, custom_claims={"roles": ["user", "guest"]})
    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_current_admin_user(current_user=user_not_admin)
    assert excinfo.value.status_code == status.HTTP_403_FORBIDDEN


# --- Testes para get_api_key ---
import secrets  # Importar secrets (movido para cima, mas ok)

async def test_get_api_key_success(monkeypatch):
    """Test successful API key validation."""
    valid_key = secrets.token_hex(32)
    monkeypatch.setattr(settings, "INTERNAL_API_KEY", valid_key)
    result = await dependencies.get_api_key(api_key=valid_key)
    assert result == valid_key

async def test_get_api_key_invalid(monkeypatch):
    """Test validation failure with incorrect API key."""
    correct_key = secrets.token_hex(32)
    incorrect_key = "invalid-key-string"
    monkeypatch.setattr(settings, "INTERNAL_API_KEY", correct_key)
    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_api_key(api_key=incorrect_key)
    assert excinfo.value.status_code == status.HTTP_401_UNAUTHORIZED
    assert "inválida ou ausente" in excinfo.value.detail

async def test_get_api_key_not_configured(monkeypatch):
    """Test failure when INTERNAL_API_KEY is not set."""
    monkeypatch.setattr(settings, "INTERNAL_API_KEY", None)  # Simulate not set
    with pytest.raises(HTTPException) as excinfo:
        await dependencies.get_api_key(api_key="any-key")
    assert excinfo.value.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert "não está configurada" in excinfo.value.detail