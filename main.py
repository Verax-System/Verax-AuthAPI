# auth_api/main.py
import os
import json # Para carregar as chaves JWK
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
# --- Imports de Segurança (FastAPI) ---
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader, HTTPBearer

# --- Imports slowapi (Rate Limiting) ---
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

# --- Imports da sua Aplicação ---
from app.db.session import dispose_engine
from app.api.endpoints import auth, users, mgmt # Seus routers existentes
from app.api.dependencies import get_api_key, oauth2_scheme, bearer_scheme, api_key_scheme # Suas dependências existentes
from app.core.config import settings # Importar settings para carregar as chaves
from app.db.base import Base # noqa - Importar Base para Alembic
# Importar todos os modelos para Alembic/Base.metadata
from app.models import ( # noqa
    user, refresh_token, mfa_recovery_code, trusted_device,
    oauth2_client, oauth2_authorization_code
)

# --- Authlib Imports ---
from authlib.integrations.starlette_oauth2 import AuthorizationServer
from authlib.oauth2.rfc6749 import grants # OAuth2 Grants
from authlib.oidc.core import grants as oidc_grants # OpenID Connect Grants
from authlib.jose import JsonWebKey # Para carregar JWK

# --- Funções Ponte OIDC (do ficheiro oidc_server.py) ---
from app.oidc_server import (
    query_client,
    save_token,
    query_authorization_code,
    delete_authorization_code,
    authenticate_user_for_oidc,
    # generate_user_info # Importaremos quando usarmos
)
from app.models.user import User as UserModel # Para type hints

# --- Carregar Chaves JWK das Configurações ---
try:
    private_jwk_json_str = settings.OIDC_PRIVATE_JWK_JSON
    public_jwk_set_json_str = settings.OIDC_PUBLIC_JWK_SET_JSON

    if not private_jwk_json_str or not public_jwk_set_json_str:
        raise ValueError("Variáveis OIDC_PRIVATE_JWK_JSON ou OIDC_PUBLIC_JWK_SET_JSON não definidas.")

    PRIVATE_JWK = json.loads(private_jwk_json_str)
    JWK_SET = json.loads(public_jwk_set_json_str)

    # Validar minimamente se as chaves parecem corretas
    if 'keys' not in JWK_SET or not isinstance(JWK_SET['keys'], list) or not JWK_SET['keys']:
        raise ValueError("OIDC_PUBLIC_JWK_SET_JSON inválido: deve ser um JWKSet com uma lista 'keys'.")
    if 'kty' not in PRIVATE_JWK:
         raise ValueError("OIDC_PRIVATE_JWK_JSON inválido: não parece ser uma chave JWK.")

    print(f"INFO: Chaves JWK OIDC carregadas com sucesso a partir da configuração (kty: {PRIVATE_JWK.get('kty')}).")

except (AttributeError, ValueError, json.JSONDecodeError) as e:
    print(f"ERRO FATAL: Falha ao carregar ou parsear as chaves JWK OIDC da configuração: {e}")
    print("Verifique as variáveis OIDC_PRIVATE_JWK_JSON e OIDC_PUBLIC_JWK_SET_JSON no seu .env ou ambiente.")
    exit(1) # Sair se as chaves não puderem ser carregadas

# --- Configuração do FastAPI ---
limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])

app = FastAPI(
    title="Auth API",
    description="API Centralizada de Autenticação com OIDC",
    version="1.1.0", # Versão incrementada
    openapi_components={
        "securitySchemes": {
            "OAuth2PasswordBearer": oauth2_scheme,
            "BearerAuth": bearer_scheme,
            "APIKeyHeader": api_key_scheme
        }
    }
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:8000",
    # Adicione aqui as origens do seu frontend
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Configuração do Servidor Authlib OIDC ---
server = AuthorizationServer(
    query_client=query_client,
    save_token=save_token,
)

def configure_oidc_grants(server: AuthorizationServer):
    """Configura e regista os fluxos (grants) OIDC no servidor Authlib."""
    # 1. Fluxo Principal: Authorization Code Flow (com OpenID Connect)
    server.register_grant(
        oidc_grants.OpenIDAuthorizationCodeGrant,
        [
            authenticate_user_for_oidc, # Hook para obter o utilizador a partir do código
        ]
    )
    # 2. Código de Autorização (necessário pelo grant acima)
    server.register_grant(
        grants.AuthorizationCodeGrant,
        [
            query_authorization_code, # Como encontrar um código
            delete_authorization_code, # Como deletar um código após uso
            authenticate_user_for_oidc, # Como obter o utilizador do código
        ]
    )
    # 3. Fluxo de Refresh Token (para clientes OIDC)
    server.register_grant(grants.RefreshTokenGrant)

# Chamar a configuração dos grants
configure_oidc_grants(server)

# --- Registrar Roteadores da API Existente ---
api_prefix = "/api/v1"

app.include_router(
    auth.router,
    prefix=f"{api_prefix}/auth",
    tags=["Authentication"],
)
app.include_router(
    users.router,
    prefix=f"{api_prefix}/users",
    tags=["Users"],
)
app.include_router(
    mgmt.router,
    prefix=f"{api_prefix}/mgmt",
    tags=["Management"],
    dependencies=[Depends(get_api_key)],
)

# --- NOVOS Endpoints OIDC ---

# 1. Endpoint de Descoberta OIDC
@app.get('/.well-known/openid-configuration')
async def openid_configuration():
    """Retorna os metadados do servidor OIDC."""
    # Usa o JWT_ISSUER definido nas settings (que deve ser a URL base)
    issuer_url = settings.JWT_ISSUER
    if not issuer_url or not issuer_url.startswith("http"):
         # Fallback, mas idealmente JWT_ISSUER deve ser a URL base correta no .env
         issuer_url = "http://localhost:8001"
         print(f"AVISO: JWT_ISSUER não é uma URL válida nas settings. Usando fallback: {issuer_url}")

    return server.generate_metadata(
        issuer=issuer_url,
        authorization_endpoint=f'{issuer_url}/oauth/authorize',
        token_endpoint=f'{issuer_url}/oauth/token',
        jwks_uri=f'{issuer_url}/oauth/jwks',
        userinfo_endpoint=f'{issuer_url}/oauth/userinfo', # Implementaremos depois
        # revocation_endpoint=f'{issuer_url}/oauth/revoke', # Implementaremos depois
        # end_session_endpoint=f'{issuer_url}/oauth/logout', # Implementaremos depois
    )

# 2. Endpoint JWKS (Chaves Públicas)
@app.get('/oauth/jwks')
async def jwks_uri():
    """Retorna as chaves públicas (JWKSet) usadas para assinar os ID Tokens."""
    return JWK_SET

# (Os endpoints /oauth/authorize e /oauth/token serão adicionados no próximo passo)


# --- Evento de Shutdown e Rota Raiz ---
@app.on_event("shutdown")
async def shutdown_event():
    print("Shutting down: Disposing database engine...")
    await dispose_engine()
    print("Database engine disposed.")

@app.get("/")
def read_root():
    return {"message": "Auth API with OIDC support is running!"}

# --- Middleware para injetar estado Authlib ---
@app.middleware("http")
async def add_authlib_server_state(request: Request, call_next):
    request.state.oauth2_server = server
    request.state.oidc_private_jwk = PRIVATE_JWK
    response = await call_next(request)
    return response