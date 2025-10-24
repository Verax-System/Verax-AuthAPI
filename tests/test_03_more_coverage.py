# tests/test_03_more_coverage.py

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch, AsyncMock
from datetime import datetime, timedelta, timezone
from fastapi import status, HTTPException
from jose import jwt # type: ignore

from app.models.user import User
from app.crud.crud_user import user as crud_user
from app.crud import crud_refresh_token, crud_mfa_recovery_code
from app.schemas.user import UserCreate
from app.core import security
from app.core.config import settings
from app.api.dependencies import get_current_admin_user # Importar dependência
# Importar a fixture do outro arquivo ou recriá-la aqui se necessário
# Se for recriar, certifique-se que ela cria um usuário ativo e verificado.
# Usaremos as fixtures do test_02_coverage_increase.py assumindo que elas rodam antes.

# Marcar todos os testes como asyncio
pytestmark = pytest.mark.asyncio

# --- CONSTANTES ---
# Reutilizar constantes dos outros arquivos se necessário
TEST_EMAIL_COV = "coverage@example.com"
TEST_PASSWORD_COV = "CoveragePass123!"
TEST_EMAIL_ADMIN = "admin_cov@example.com"

# --- Testes Adicionais para Cobertura ---

@pytest.mark.asyncio
async def test_get_current_admin_user_no_claims(db_session: AsyncSession, active_user_cov: User):
    """Testa a LÓGICA de admin quando o usuário não tem custom_claims."""
    user = active_user_cov
    user.custom_claims = None
    # Não precisa commitar ou refrescar aqui, estamos apenas a testar a lógica da função

    with pytest.raises(HTTPException) as exc_info:
        # Chama a função diretamente com o objeto user preparado
        await get_current_admin_user(current_user=user)
    assert exc_info.value.status_code == 403
    assert "Requer privilégios de administrador" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_current_admin_user_claims_no_roles(db_session: AsyncSession, active_user_cov: User):
    """Testa a LÓGICA de admin quando custom_claims existe mas não tem 'roles'."""
    user = active_user_cov
    user.custom_claims = {"permissions": ["read"]}

    with pytest.raises(HTTPException) as exc_info:
        await get_current_admin_user(current_user=user)
    assert exc_info.value.status_code == 403
    assert "Requer privilégios de administrador" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_current_admin_user_roles_not_list(db_session: AsyncSession, active_user_cov: User):
    """Testa a LÓGICA de admin quando 'roles' em custom_claims não é uma lista."""
    user = active_user_cov
    user.custom_claims = {"roles": "admin"} # 'roles' é uma string

    with pytest.raises(HTTPException) as exc_info:
        await get_current_admin_user(current_user=user)
    assert exc_info.value.status_code == 403
    assert "Requer privilégios de administrador" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_current_admin_user_roles_list_no_admin(db_session: AsyncSession, active_user_cov: User):
    """Testa a LÓGICA de admin quando 'roles' é lista mas não contém 'admin'."""
    user = active_user_cov
    user.custom_claims = {"roles": ["user", "beta"]} # Lista sem 'admin'

    with pytest.raises(HTTPException) as exc_info:
        await get_current_admin_user(current_user=user)
    assert exc_info.value.status_code == 403
    assert "Requer privilégios de administrador" in exc_info.value.detail

@pytest.mark.asyncio
async def test_get_current_admin_user_success(db_session: AsyncSession, active_user_cov: User):
    """Testa a LÓGICA de admin quando 'roles' contém 'admin'."""
    user = active_user_cov
    user.custom_claims = {"roles": ["user", "admin"]} # Lista COM 'admin'

    # Não deve levantar exceção
    result_user = await get_current_admin_user(current_user=user)
    assert result_user == user # Deve retornar o próprio usuário

# --- Corrigir testes MFA que usam active_user_cov ---
# Os erros AttributeError: 'AsyncSession' object has no attribute 'refresh'
# acontecem porque active_user_cov já vem com commit/refresh da fixture.
# Não precisamos fazer commit/refresh novamente dentro desses testes.

@pytest.mark.asyncio
async def test_verify_mfa_login_invalid_user_state(
    async_client: AsyncClient, db_session: AsyncSession, active_user_cov: User
):
    """Testa POST /mfa/verify quando o usuário está inativo ou MFA desabilitado após challenge."""
    user = active_user_cov
    challenge_token = security.create_mfa_challenge_token(user_id=user.id)

    # Alterar estado do usuário
    user.is_active = False # Tornar inativo
    db_session.add(user)
    await db_session.commit()
    # await db_session.refresh(user) # REMOVER refresh aqui

    # Tentar verificar MFA
    response = await async_client.post("/api/v1/auth/mfa/verify", json={
        "mfa_challenge_token": challenge_token,
        "otp_code": "123456"
    })
    assert response.status_code == 400
    assert "Usuário inválido ou MFA não está (mais) habilitado" in response.json()["detail"]

    # Reativar e desabilitar MFA
    user.is_active = True
    user.is_mfa_enabled = False
    user.otp_secret = None
    db_session.add(user)
    await db_session.commit()
    # await db_session.refresh(user) # REMOVER refresh aqui

    # Tentar verificar MFA novamente
    response = await async_client.post("/api/v1/auth/mfa/verify", json={
        "mfa_challenge_token": challenge_token,
        "otp_code": "123456"
    })
    assert response.status_code == 400
    assert "Usuário inválido ou MFA não está (mais) habilitado" in response.json()["detail"]


@pytest.mark.asyncio
async def test_verify_mfa_recovery_login_invalid_user_state(
    async_client: AsyncClient, db_session: AsyncSession, active_user_cov: User
):
    """Testa POST /mfa/verify-recovery quando o usuário está inativo ou MFA desabilitado após challenge."""
    user = active_user_cov
    challenge_token = security.create_mfa_challenge_token(user_id=user.id)

    # Tornar inativo
    user.is_active = False
    db_session.add(user)
    await db_session.commit()
    # await db_session.refresh(user) # REMOVER refresh aqui

    # Tentar verificar com recovery code
    response = await async_client.post("/api/v1/auth/mfa/verify-recovery", json={
        "mfa_challenge_token": challenge_token,
        "recovery_code": "abc-123"
    })
    assert response.status_code == 400
    assert "Usuário inválido ou MFA não está habilitado" in response.json()["detail"]

    # Reativar e desabilitar MFA
    user.is_active = True
    user.is_mfa_enabled = False
    db_session.add(user)
    await db_session.commit()
    # await db_session.refresh(user) # REMOVER refresh aqui

    # Tentar verificar novamente
    response = await async_client.post("/api/v1/auth/mfa/verify-recovery", json={
        "mfa_challenge_token": challenge_token,
        "recovery_code": "abc-123"
    })
    assert response.status_code == 400
    assert "Usuário inválido ou MFA não está habilitado" in response.json()["detail"]