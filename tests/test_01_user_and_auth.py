import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy.future import select # <-- REMOVIDO F401

from app.models.user import User

# Marcar todos os testes neste arquivo como 'asyncio'
pytestmark = pytest.mark.asyncio

# Dados de teste
TEST_EMAIL = "test@example.com"
TEST_PASSWORD = "Password123!" # Senha que passa na validação
WEAK_PASSWORD = "123"

@pytest.mark.asyncio
async def test_register_user_success(async_client: AsyncClient, db_session: AsyncSession):
    """Testa o registro de usuário com sucesso."""
    response = await async_client.post("/api/v1/users/", json={
        "email": TEST_EMAIL,
        "password": TEST_PASSWORD,
        "full_name": "Test User"
    })

    assert response.status_code == 201
    data = response.json()
    assert data["email"] == TEST_EMAIL
    assert data["full_name"] == "Test User"
    assert "id" in data

    # Verificar se o usuário foi realmente salvo no BD de teste
    user = await db_session.get(User, data["id"])
    assert user is not None
    assert user.email == TEST_EMAIL
    assert not user.is_active # <-- CORRIGIDO E712 (era == False)

@pytest.mark.asyncio
async def test_register_user_duplicate_email(async_client: AsyncClient):
    """Testa a falha ao registrar um email duplicado."""
    # Criar o primeiro usuário
    await async_client.post("/api/v1/users/", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": "Test User 1"
    })

    # Tentar criar o segundo com o mesmo email
    response = await async_client.post("/api/v1/users/", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": "Test User 2"
    })

    assert response.status_code == 400
    assert "email already exists" in response.json()["detail"]

@pytest.mark.asyncio
async def test_register_user_weak_password(async_client: AsyncClient):
    """Testa a falha ao registrar com uma senha fraca."""
    response = await async_client.post("/api/v1/users/", json={
        "email": TEST_EMAIL, "password": WEAK_PASSWORD, "full_name": "Test User"
    })

    # 422 Unprocessable Entity (Erro de validação do Pydantic)
    assert response.status_code == 422
    assert "A senha deve ter pelo menos 8 caracteres" in response.text

@pytest.mark.asyncio
async def test_login_user_not_verified(async_client: AsyncClient, db_session: AsyncSession):
    """Testa o login de um usuário que ainda não verificou o email."""
    # Registrar (usuário fica como is_active=False)
    await async_client.post("/api/v1/users/", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": "Test User"
    })

    # Tentar logar
    response = await async_client.post("/api/v1/auth/token", data={
        "username": TEST_EMAIL,
        "password": TEST_PASSWORD
    })

    assert response.status_code == 400
    assert "Conta inativa ou e-mail não verificado" in response.json()["detail"]

@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient, db_session: AsyncSession):
    """Testa o fluxo de login completo (com ativação manual)."""
    # 1. Registrar
    reg_response = await async_client.post("/api/v1/users/", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": "Test User"
    })
    user_id = reg_response.json()["id"]

    # 2. Ativar o usuário manualmente (simulando a verificação de email)
    user = await db_session.get(User, user_id)
    user.is_active = True
    user.is_verified = True
    db_session.add(user)
    await db_session.commit()

    # 3. Tentar logar
    login_response = await async_client.post("/api/v1/auth/token", data={
        "username": TEST_EMAIL,
        "password": TEST_PASSWORD
    })

    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

@pytest.mark.asyncio
async def test_get_me(async_client: AsyncClient, db_session: AsyncSession):
    """Testa o endpoint protegido /me."""
    # 1. Registrar e Ativar
    reg_response = await async_client.post("/api/v1/users/", json={
        "email": TEST_EMAIL, "password": TEST_PASSWORD, "full_name": "Test User"
    })
    user = await db_session.get(User, reg_response.json()["id"])
    user.is_active = True
    user.is_verified = True
    db_session.add(user)
    await db_session.commit()

    # 2. Logar para pegar o token
    login_response = await async_client.post("/api/v1/auth/token", data={
        "username": TEST_EMAIL, "password": TEST_PASSWORD
    })
    access_token = login_response.json()["access_token"]

    # 3. Chamar o /me com o token
    headers = {"Authorization": f"Bearer {access_token}"}
    me_response = await async_client.get("/api/v1/users/me", headers=headers)

    assert me_response.status_code == 200
    data = me_response.json()
    assert data["email"] == TEST_EMAIL
    assert data["id"] == user.id