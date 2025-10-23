# tests/test_05_refresh_logout.py
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
import time

from app.models.user import User
from app.models.refresh_token import RefreshToken
from app.core import security
from sqlalchemy.future import select

pytestmark = pytest.mark.asyncio

TEST_EMAIL = "refresh@example.com"
TEST_PASSWORD = "PasswordRefresh123!"


async def create_and_login_user(
    async_client: AsyncClient, db_session: AsyncSession
) -> tuple[str, str, int]:
    """Helper: Cria, ativa e loga um usuário, retornando token de acesso, refresh e ID."""
    reg_response = await async_client.post(
        "/api/v1/users/",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "full_name": "Refresh Test User",
        },
    )
    assert reg_response.status_code == 201
    user_id = reg_response.json()["id"]

    # Ativar
    user = await db_session.get(User, user_id)
    assert user is not None
    user.is_active = True
    user.is_verified = True
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # Logar
    login_response = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert login_response.status_code == 200
    tokens = login_response.json()
    return tokens["access_token"], tokens["refresh_token"], user_id


async def test_refresh_token(async_client: AsyncClient, db_session: AsyncSession):
    """Testa o fluxo de refresh token."""
    access_token, refresh_token, user_id = await create_and_login_user(
        async_client, db_session
    )
    original_decoded_access = security.decode_access_token(access_token)
    original_decoded_refresh = security.decode_refresh_token(refresh_token)

    assert original_decoded_access is not None
    assert original_decoded_refresh is not None

    # Esperar um pouco para garantir que os novos tokens tenham timestamps diferentes
    time.sleep(1)

    # Usar o refresh token para obter novos tokens
    refresh_response = await async_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert refresh_response.status_code == 200
    new_tokens = refresh_response.json()
    new_access_token = new_tokens["access_token"]
    new_refresh_token = new_tokens["refresh_token"]

    assert new_access_token != access_token
    assert new_refresh_token != refresh_token

    # Verificar se os novos tokens são válidos e têm timestamps atualizados
    new_decoded_access = security.decode_access_token(new_access_token)
    new_decoded_refresh = security.decode_refresh_token(new_refresh_token)

    assert new_decoded_access is not None
    assert new_decoded_refresh is not None
    assert new_decoded_access["sub"] == str(user_id)
    assert new_decoded_refresh["sub"] == str(user_id)
    assert new_decoded_access["exp"] > original_decoded_access["exp"]
    # O refresh token pode ou não ter um 'exp' maior, dependendo da implementação exata,
    # mas deve ser diferente do original se a rotação ocorreu.

    # Verificar no BD se o refresh token ANTIGO foi revogado
    old_refresh_hash = security.hash_token(
        refresh_token
    )  # Assumindo que você tem hash_token em security
    stmt_old = select(RefreshToken).where(RefreshToken.token_hash == old_refresh_hash)
    result_old = await db_session.execute(stmt_old)
    old_db_token = result_old.scalars().first()
    # A implementação atual DELETA tokens antigos, então ele não deve ser encontrado
    # Se a implementação APENAS revogasse, o assert seria: assert old_db_token.is_revoked is True
    assert old_db_token is None

    # Verificar se o NOVO refresh token existe no BD e não está revogado
    new_refresh_hash = security.hash_token(new_refresh_token)
    stmt_new = select(RefreshToken).where(RefreshToken.token_hash == new_refresh_hash)
    result_new = await db_session.execute(stmt_new)
    new_db_token = result_new.scalars().first()
    assert new_db_token is not None
    assert new_db_token.is_revoked is False
    assert new_db_token.user_id == user_id

    # Tentar usar o refresh token ANTIGO novamente (deve falhar)
    refresh_response_old = await async_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert refresh_response_old.status_code == 401  # Unauthorized


async def test_logout(async_client: AsyncClient, db_session: AsyncSession):
    """Testa o endpoint de logout revogando o refresh token."""
    _, refresh_token, user_id = await create_and_login_user(async_client, db_session)

    refresh_hash = security.hash_token(refresh_token)

    # Verificar que o token existe e não está revogado antes do logout
    stmt_before = select(RefreshToken).where(RefreshToken.token_hash == refresh_hash)
    result_before = await db_session.execute(stmt_before)
    db_token_before = result_before.scalars().first()
    assert db_token_before is not None
    assert db_token_before.is_revoked is False

    # Chamar o endpoint de logout
    logout_response = await async_client.post(
        "/api/v1/auth/logout", json={"refresh_token": refresh_token}
    )
    assert logout_response.status_code == 204  # No Content

    # Verificar no BD se o token foi marcado como revogado
    # Nota: A implementação atual DELETA o token ao criar um novo, mas o logout APENAS revoga.
    # Precisamos buscar novamente.
    await db_session.expire(
        db_token_before
    )  # Força o SQLAlchemy a buscar do BD de novo
    stmt_after = select(RefreshToken).where(RefreshToken.token_hash == refresh_hash)
    result_after = await db_session.execute(stmt_after)
    db_token_after = result_after.scalars().first()

    assert db_token_after is not None  # Ele ainda existe
    assert db_token_after.is_revoked is True  # Mas está revogado

    # Tentar usar o refresh token revogado (deve falhar)
    refresh_response_revoked = await async_client.post(
        "/api/v1/auth/refresh", json={"refresh_token": refresh_token}
    )
    assert refresh_response_revoked.status_code == 401  # Unauthorized
