import os
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.models.user import User
from app.core.config import settings
from app.core.security import get_password_hash # Importar get_password_hash

pytestmark = pytest.mark.asyncio

MAX_ATTEMPTS = settings.LOGIN_MAX_FAILED_ATTEMPTS
EMAIL = "lockout@example.com"
PASSWORD = "Password123!"
WRONG_PASSWORD = "WrongPassword123!"

async def setup_active_user(async_client: AsyncClient, db_session: AsyncSession) -> int:
    """Helper para criar/resetar e ativar um usuário para os testes de lockout."""
    # Buscar usuário pelo email
    user_result = await db_session.execute(select(User).where(User.email == EMAIL))
    user = user_result.scalars().first()

    if user:
        # Se existir, resetar estado
        user_id = user.id
        print(f"User {EMAIL} already exists, resetting state for lockout test. ID: {user_id}")
        user.is_active = True
        user.is_verified = True
        user.failed_login_attempts = 0 # Garantir que começa zerado
        user.locked_until = None      # Garantir que começa desbloqueado
        user.hashed_password = get_password_hash(PASSWORD) # Garantir senha correta
    else:
        # Se não existe, criar
        print(f"Creating user {EMAIL} for lockout test.")
        reg_response = await async_client.post("/api/v1/users/", json={
            "email": EMAIL, "password": PASSWORD, "full_name": "Lockout User"
        })
        assert reg_response.status_code == 201, f"Failed to register user: {reg_response.json()}"
        user_id = reg_response.json()["id"]
        user = await db_session.get(User, user_id)
        assert user is not None
        user.is_active = True
        user.is_verified = True
        user.failed_login_attempts = 0 # Definir explicitamente
        user.locked_until = None      # Definir explicitamente

    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    print(f"User {EMAIL} setup complete. Attempts: {user.failed_login_attempts}, Locked: {user.locked_until}")
    return user_id

@pytest.mark.asyncio
async def test_account_lockout(async_client: AsyncClient, db_session: AsyncSession):
    """
    Testa o bloqueio de conta após N tentativas falhas e verifica a mensagem.
    """
    user_id = await setup_active_user(async_client, db_session)

    print(f"Testando bloqueio após {MAX_ATTEMPTS} tentativas falhas...")

    # Tentar logar com senha errada MAX_ATTEMPTS vezes para ATIVAR o bloqueio
    for i in range(MAX_ATTEMPTS):
        print(f"Tentativa falha {i+1}/{MAX_ATTEMPTS}...")
        response = await async_client.post("/api/v1/auth/token", data={
            "username": EMAIL,
            "password": WRONG_PASSWORD
        })
        # As N tentativas falhas retornam 400 "Incorrect"
        assert response.status_code == 400, f"Attempt {i+1} failed with status {response.status_code}"
        assert "Incorrect email or password" in response.json()["detail"], f"Attempt {i+1} response: {response.json()['detail']}"

        # Verificar no BD o estado APÓS a tentativa i
        user_check = await db_session.get(User, user_id)
        await db_session.refresh(user_check)
        print(f"Após tentativa {i+1}: Attempts={user_check.failed_login_attempts}, LockedUntil={user_check.locked_until}")

        # --- CORREÇÃO NA LÓGICA DA ASSERTIVA ---
        if i < MAX_ATTEMPTS - 1:
            # Nas tentativas ANTES da última, a contagem sobe e não há bloqueio
            assert user_check.failed_login_attempts == i + 1
            assert user_check.locked_until is None
        else:
            # NA ÚLTIMA tentativa (i == MAX_ATTEMPTS - 1), a contagem reseta para 0
            # E o locked_until é DEFINIDO
            assert user_check.failed_login_attempts == 0
            assert user_check.locked_until is not None
        # --- FIM CORREÇÃO ---

    # Fazer a tentativa SEGUINTE (N+1) para verificar a mensagem
    print("Verificando mensagem de bloqueio na tentativa seguinte...")
    locked_response = await async_client.post("/api/v1/auth/token", data={
        "username": EMAIL,
        "password": PASSWORD # Usar senha correta para isolar o motivo da falha
    })

    # ESTA tentativa deve falhar com 400 e a mensagem "Account locked"
    assert locked_response.status_code == 400, f"Status code after lock should be 400, got {locked_response.status_code}"
    assert "Account locked" in locked_response.json()["detail"], f"Response detail after lock: {locked_response.json()['detail']}"

@pytest.mark.asyncio
async def test_login_resets_failed_attempts(async_client: AsyncClient, db_session: AsyncSession):
    """Testa se um login bem-sucedido zera as tentativas falhas."""
    user_id = await setup_active_user(async_client, db_session)

    # Tentar logar com senha errada (menos que o MAX)
    attempts_to_fail = MAX_ATTEMPTS - 1
    print(f"Fazendo {attempts_to_fail} tentativas falhas...")
    for i in range(attempts_to_fail):
        response = await async_client.post("/api/v1/auth/token", data={
            "username": EMAIL,
            "password": WRONG_PASSWORD
        })
        assert response.status_code == 400

    # Verificar no BD que as tentativas falhas foram registradas
    user_before_login = await db_session.get(User, user_id)
    assert user_before_login is not None
    await db_session.refresh(user_before_login)
    print(f"Tentativas falhas antes do login: {user_before_login.failed_login_attempts}")
    assert user_before_login.failed_login_attempts == attempts_to_fail
    assert user_before_login.locked_until is None

    # Logar com sucesso
    print("Tentando logar com sucesso...")
    login_response = await async_client.post("/api/v1/auth/token", data={
        "username": EMAIL,
        "password": PASSWORD
    })
    if login_response.status_code != 200:
        print("Falha no login que deveria resetar:", login_response.json()) # Debug
    assert login_response.status_code == 200

    # Verificar no BD se as tentativas foram zeradas
    user_after_login = await db_session.get(User, user_id)
    assert user_after_login is not None
    await db_session.refresh(user_after_login)
    print(f"Tentativas falhas após login sucesso: {user_after_login.failed_login_attempts}")
    assert user_after_login.failed_login_attempts == 0
    assert user_after_login.locked_until is None