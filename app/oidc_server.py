# auth_api/app/oidc_server.py
import time
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from authlib.oauth2.rfc6749 import ClientMixin, TokenMixin, AuthorizationCodeMixin
from authlib.oidc.core import UserInfo

# Importar modelos e CRUDs necessários
from app.models.oauth2_client import OAuth2Client
from app.models.oauth2_authorization_code import OAuth2AuthorizationCode
from app.models.refresh_token import RefreshToken # Reutilizaremos esta
from app.models.user import User
from app.crud import crud_refresh_token # Para interagir com refresh tokens
from app.core.security import pwd_context # Para verificar client_secret
from app.db.session import get_db # Para obter a sessão async

# --- Implementações para Authlib ---

async def query_client(client_id: str) -> Optional[OAuth2Client]:
    """Função que o Authlib usa para encontrar um cliente OIDC pelo seu client_id."""
    async for db in get_db(): # Obtém a sessão async
        stmt = select(OAuth2Client).where(OAuth2Client.client_id == client_id)
        result = await db.execute(stmt)
        client = result.scalars().first()
        # NOTA: Authlib espera um objeto que implemente ClientMixin.
        # Nosso modelo OAuth2Client já tem os métodos necessários.
        return client # Retorna o objeto SQLAlchemy diretamente

async def save_token(token: Dict[str, Any], request: Any) -> None:
    """
    Função que o Authlib usa para *salvar* os tokens gerados (access e refresh).
    Nós só salvaremos o refresh token na nossa tabela `refresh_tokens`.
    """
    # O objeto 'request' aqui é do Authlib e contém informações úteis
    client: OAuth2Client = request.client
    user: User = request.user

    if token.get("token_type") == "Bearer" and token.get("refresh_token"):
        # Estamos interessados apenas no refresh_token
        refresh_token_str = token["refresh_token"]
        expires_in = token.get("expires_in", 0)
        expires_at = datetime.fromtimestamp(int(time.time()) + expires_in, tz=timezone.utc).replace(tzinfo=None)

        # Reutiliza o CRUD existente para refresh tokens
        async for db in get_db():
             # Aqui poderíamos passar IP/User-Agent se quiséssemos rastrear sessões OIDC também
            await crud_refresh_token.create_refresh_token(
                db,
                user=user,
                token=refresh_token_str,
                expires_at=expires_at
                # Opcional: Adicionar ip_address=..., user_agent=... se capturado
            )
            # Nota: Não salvamos o access_token porque ele é um JWT auto-contido.

async def query_authorization_code(code: str, client: OAuth2Client) -> Optional[OAuth2AuthorizationCode]:
    """Função que o Authlib usa para encontrar um código de autorização."""
    async for db in get_db():
        stmt = select(OAuth2AuthorizationCode).where(
            OAuth2AuthorizationCode.code == code,
            OAuth2AuthorizationCode.client_id == client.client_id # Garante que o código pertence ao cliente
        )
        result = await db.execute(stmt)
        auth_code = result.scalars().first()
        if auth_code and not auth_code.is_expired():
            return auth_code
        return None

async def delete_authorization_code(authorization_code: OAuth2AuthorizationCode) -> None:
    """Função que o Authlib usa para deletar um código após ele ser usado."""
    async for db in get_db():
        await db.delete(authorization_code)
        await db.commit()

async def authenticate_user_for_oidc(authorization_code: OAuth2AuthorizationCode) -> Optional[User]:
    """
    Função que o Authlib usa para obter o objeto User associado a um código
    de autorização (usado principalmente durante a troca de código por token).
    """
    async for db in get_db():
        stmt = select(User).where(User.id == authorization_code.user_id)
        result = await db.execute(stmt)
        return result.scalars().first()

# --- Helpers Adicionais (Exemplo) ---

def generate_user_info(user: User, scope: str) -> UserInfo:
    """
    Gera o objeto UserInfo para o ID Token e o endpoint UserInfo,
    baseado nos scopes solicitados.
    """
    # O scope 'openid' é obrigatório e sempre retorna 'sub' (subject ID)
    user_info = UserInfo(sub=str(user.id))

    # Adiciona claims baseados nos scopes
    scopes = set(scope.split())
    if "profile" in scopes:
        user_info["name"] = user.full_name
        # Adicione outros claims de perfil que você tenha (picture, website, etc.)
    if "email" in scopes:
        user_info["email"] = user.email
        user_info["email_verified"] = user.is_verified

    # Adicione seus custom claims aqui se um scope específico for solicitado
    # Ex: if "roles" in scopes and user.custom_claims and "roles" in user.custom_claims:
    #         user_info["roles"] = user.custom_claims["roles"]

    return user_info

# Importações adicionadas no topo
from datetime import datetime, timezone