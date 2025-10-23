import os
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.models.user import User
from app.core.config import settings # Importar settings

pytestmark = pytest.mark.asyncio

# Pegar as configurações do .env (que o 'settings' já carregou)
MAX_ATTEMPTS = settings.LOGIN_MAX_FAILED_ATTEMPTS
EMAIL = "lockout@example.com"
PASSWORD = "Password123!"
WRONG_PASSWORD = "WrongPassword123!"

async def setup_active_user(async_client: AsyncClient, db_session: AsyncSession):
    """Helper para criar e ativar um usuário para os testes de lockout."""
    reg_response = await async_client.post("/api/v1/users/", json={
        "email": EMAIL, "password": PASSWORD, "full_name": "Lockout User"
    })
    assert reg_response.status_code == 201
    user_id = reg_response.json()["id"]

    # Ativar o usuário manualmente
    user = await db_session.get(User, user_id)
    user.is_active = True
    user.is_verified = True
    db_session.add(user)
    await db_session.commit()
    return user_id

@pytest.mark.asyncio
async def test_account_lockout(async_client: AsyncClient, db_session: AsyncSession):
    """
    Testa o bloqueio de conta após N tentativas falhas.
    NOTA: Este teste não espera o tempo real de bloqueio (ex: 15 min),
    ele apenas verifica se o bloqueio é ATIVADO.
    """
    await setup_active_user(async_client, db_session)
    
    print(f"Testando bloqueio após {MAX_ATTEMPTS} tentativas...")

    # Tentar logar com senha errada MAX_ATTEMPTS vezes
    for i in range(MAX_ATTEMPTS):
        response = await async_client.post("/api/v1/auth/token", data={
            "username": EMAIL,
            "password": WRONG_PASSWORD
        })
        # As primeiras N-1 tentativas devem falhar com "Incorrect"
        if i < MAX_ATTEMPTS - 1:
            assert response.status_code == 400
            assert "Incorrect email or password" in response.json()["detail"]
        else:
            # A última tentativa deve retornar "Account locked"
            assert response.status_code == 400
            assert "Account locked" in response.json()["detail"]

    # Tentar logar com a SENHA CORRETA agora
    final_response = await async_client.post("/api/v1/auth/token", data={
        "username": EMAIL,
        "password": PASSWORD
    })
    
    # Deve falhar, pois a conta está bloqueada
    assert final_response.status_code == 400
    assert "Account locked" in final_response.json()["detail"]

@pytest.mark.asyncio
async def test_login_resets_failed_attempts(async_client: AsyncClient, db_session: AsyncSession):
    """Testa se um login bem-sucedido zera as tentativas falhas."""
    user_id = await setup_active_user(async_client, db_session)
    
    # Tentar logar com senha errada (menos que o MAX)
    for _ in range(MAX_ATTEMPTS - 1):
        await async_client.post("/api/v1/auth/token", data={
            "username": EMAIL,
            "password": WRONG_PASSWORD
        })

    # Verificar no BD que as tentativas falhas foram registradas
    user = await db_session.get(User, user_id)
    assert user.failed_login_attempts == MAX_ATTEMPTS - 1
    
    # Logar com sucesso
    login_response = await async_client.post("/api/v1/auth/token", data={
        "username": EMAIL,
        "password": PASSWORD
    })
    assert login_response.status_code == 200
    
    # Verificar no BD se as tentativas foram zeradas
    await db_session.refresh(user) # Recarregar dados do BD
    assert user.failed_login_attempts == 0
    assert user.locked_until is None