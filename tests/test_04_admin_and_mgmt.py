# tests/test_04_admin_and_mgmt.py
import pytest
from sqlalchemy import select
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from app.models.user import User
from app.core.config import settings # <-- Import settings

pytestmark = pytest.mark.asyncio

ADMIN_EMAIL = "admin@example.com"
REGULAR_EMAIL = "regular@example.com"
PASSWORD = "PasswordAdmin123!"
# Use the actual setting value, falling back to a dummy if not set
MGMT_API_KEY = settings.INTERNAL_API_KEY


async def create_user(
    async_client: AsyncClient,
    db_session: AsyncSession,
    email: str,
    is_admin: bool = False,
) -> tuple[int, str]:
    """Helper: Cria, ativa um usuário e retorna ID e token de acesso."""
    # Registrar
    reg_response = await async_client.post(
        "/api/v1/users/",
        json={"email": email, "password": PASSWORD, "full_name": "Test User"}, # Nome genérico
    )
    # Handle potential duplicate emails if tests run multiple times without full cleanup
    if reg_response.status_code == 400 and "email already exists" in reg_response.text:
         user_result = await db_session.execute(select(User).where(User.email == email))
         existing_user = user_result.scalars().first()
         user_id = existing_user.id
         print(f"User {email} already exists, using existing user ID: {user_id}")
    elif reg_response.status_code == 201:
        user_id = reg_response.json()["id"]
    else:
        reg_response.raise_for_status() # Raise error for other unexpected statuses

    # Ativar e definir como admin (se necessário)
    user = await db_session.get(User, user_id)
    assert user is not None
    user.is_active = True
    user.is_verified = True
    if is_admin:
        user.custom_claims = {"roles": ["admin"]}
        flag_modified(user, "custom_claims")
    elif user.custom_claims is None or user.custom_claims.get("roles") != ["admin"]: # Only update if not already admin
        user.custom_claims = {"roles": ["user"]} # Default role maybe? Or empty {}
        flag_modified(user, "custom_claims")
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # Logar para obter token
    login_response = await async_client.post(
        "/api/v1/auth/token", data={"username": email, "password": PASSWORD}
    )
    assert login_response.status_code == 200, f"Login failed for {email}: {login_response.json()}"
    access_token = login_response.json()["access_token"]

    return user_id, access_token


@pytest.mark.asyncio
async def test_admin_endpoints(async_client: AsyncClient, db_session: AsyncSession):
    """Testa endpoints que requerem a role 'admin'."""
    admin_id, admin_token = await create_user(
        async_client, db_session, ADMIN_EMAIL, is_admin=True
    )
    regular_id, regular_token = await create_user(
        async_client, db_session, REGULAR_EMAIL, is_admin=False
    )

    admin_headers = {"Authorization": f"Bearer {admin_token}"}
    regular_headers = {"Authorization": f"Bearer {regular_token}"}

    # --- Testar GET /users/ ---
    # Admin (deve funcionar)
    response_admin_list = await async_client.get(
        "/api/v1/users/", headers=admin_headers
    )
    assert response_admin_list.status_code == 200
    users_list = response_admin_list.json()
    assert len(users_list) >= 2
    assert any(u["email"] == ADMIN_EMAIL for u in users_list)
    assert any(u["email"] == REGULAR_EMAIL for u in users_list)

    # Usuário Regular (deve falhar com 403 Forbidden)
    response_regular_list = await async_client.get(
        "/api/v1/users/", headers=regular_headers
    )
    assert response_regular_list.status_code == 403
    assert "Não autorizado" in response_regular_list.json()["detail"]

    # --- Testar GET /users/{user_id} ---
    # Admin buscando outro usuário (deve funcionar)
    response_admin_get_regular = await async_client.get(
        f"/api/v1/users/{regular_id}", headers=admin_headers
    )
    assert response_admin_get_regular.status_code == 200
    assert response_admin_get_regular.json()["email"] == REGULAR_EMAIL

    # Admin buscando ele mesmo (deve funcionar)
    response_admin_get_self = await async_client.get(
        f"/api/v1/users/{admin_id}", headers=admin_headers
    )
    assert response_admin_get_self.status_code == 200
    assert response_admin_get_self.json()["email"] == ADMIN_EMAIL

    # Usuário Regular buscando outro (deve falhar com 403 Forbidden)
    response_regular_get_admin = await async_client.get(
        f"/api/v1/users/{admin_id}", headers=regular_headers
    )
    assert response_regular_get_admin.status_code == 403

    # Usuário Regular buscando ele mesmo (deve falhar com 403 Forbidden neste endpoint)
    response_regular_get_self = await async_client.get(
        f"/api/v1/users/{regular_id}", headers=regular_headers
    )
    assert response_regular_get_self.status_code == 403


@pytest.mark.asyncio
async def test_management_api_claims(
    async_client: AsyncClient, db_session: AsyncSession
):
    """Testa a API de gerenciamento (/mgmt) para atualizar custom_claims."""
    regular_id, _ = await create_user(
        async_client, db_session, REGULAR_EMAIL, is_admin=False
    )

    # --- CORREÇÃO: Usar o valor real de settings.INTERNAL_API_KEY ---
    mgmt_headers = {"X-API-Key": MGMT_API_KEY}
    invalid_mgmt_headers = {"X-API-Key": "invalid_key"}

    # Payload de claims para adicionar/atualizar
    claims_payload = {
        "roles": ["user", "beta_tester"],
        "permissions": ["read:items"],
        "store_id": 123,
    }

    # Tentar sem API Key (deve falhar 403 - FastAPI pega antes)
    response_no_key = await async_client.patch(
        f"/api/v1/mgmt/users/{regular_id}/claims", json=claims_payload
    )
    assert response_no_key.status_code == 403

    # Tentar com API Key inválida (deve falhar 401)
    response_invalid_key = await async_client.patch(
        f"/api/v1/mgmt/users/{regular_id}/claims",
        headers=invalid_mgmt_headers,
        json=claims_payload,
    )
    assert response_invalid_key.status_code == 401
    assert "Chave de API inválida" in response_invalid_key.json()["detail"]

    # Tentar com API Key válida (deve funcionar)
    response_valid_key = await async_client.patch(
        f"/api/v1/mgmt/users/{regular_id}/claims",
        # --- CORREÇÃO: Usar o header correto ---
        headers=mgmt_headers,
        # --- FIM CORREÇÃO ---
        json=claims_payload,
    )
    # --- CORREÇÃO: A asserção original estava correta, o problema era o header ---
    assert response_valid_key.status_code == 200
    # --- FIM CORREÇÃO ---
    updated_user_data = response_valid_key.json()
    assert updated_user_data["custom_claims"] == claims_payload

    # Verificar no BD se os claims foram realmente salvos
    user = await db_session.get(User, regular_id)
    assert user is not None # Adicionar verificação
    await db_session.refresh(user) # Adicionar refresh para garantir dados atualizados
    assert user.custom_claims == claims_payload

    # Testar atualização (merge) de claims - adicionando 'new_claim'
    update_payload = {
        "permissions": ["read:items", "write:items"],
        "new_claim": True,
    }
    response_update = await async_client.patch(
        # Usar email para testar a busca por email também
        f"/api/v1/mgmt/users/{REGULAR_EMAIL}/claims",
        headers=mgmt_headers,
        json=update_payload,
    )
    assert response_update.status_code == 200
    merged_user_data = response_update.json()

    expected_merged_claims = {
        "roles": ["user", "beta_tester"],
        "permissions": ["read:items", "write:items"],
        "store_id": 123,
        "new_claim": True,
    }
    assert merged_user_data["custom_claims"] == expected_merged_claims

    # Verificar no BD
    await db_session.refresh(user)
    assert user.custom_claims == expected_merged_claims