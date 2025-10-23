# auth_api/main.py
import os  # Para verificar a variável de ambiente de teste
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

# --- Adicionar imports do slowapi ---
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
# --- Fim imports slowapi ---

from app.db.session import dispose_engine

# Importar routers
from app.api.endpoints import auth, users, mgmt

# Importar dependência de chave de API e esquemas de segurança
from app.api.dependencies import (
    get_api_key,
    oauth2_scheme,
    bearer_scheme,
    api_key_scheme,
)

# Importar modelos para Alembic/Base.metadata (importante que todos estejam aqui)
from app.db.base import Base  # noqa
from app.models import user, refresh_token, mfa_recovery_code  # noqa


# Configuração do Rate Limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])

app = FastAPI(
    title="Auth API",
    description="API Centralizada de Autenticação",
    version="1.0.0",
    # Configurações do OpenAPI para o Swagger UI reconhecer os esquemas de segurança
    openapi_components={
        "securitySchemes": {
            "OAuth2PasswordBearer": oauth2_scheme,  # Para /token
            "BearerAuth": bearer_scheme,  # Para endpoints protegidos por JWT
            "APIKeyHeader": api_key_scheme,  # Para /mgmt
        }
    },
)

# --- CORREÇÃO: Ativar o SlowAPI apenas se NÃO estiver rodando testes ---
if not os.getenv("RUNNING_TESTS"):
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    print("INFO: Rate limiter (SlowAPI) ATIVADO.")
else:
    # Log para confirmar que foi desativado no CI
    print("INFO: Rate limiter (SlowAPI) DESATIVADO para testes.")
# --- FIM DA CORREÇÃO ---


# Configuração do CORS
origins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:8000",
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir routers da API
api_prefix = "/api/v1"

# --- Router de Autenticação ---
# Proteção JWT é aplicada DENTRO dos endpoints específicos via Depends(get_current_active_user)
app.include_router(
    auth.router,
    prefix=f"{api_prefix}/auth",
    tags=["Authentication"],
)

# --- Router de Usuários ---
# Proteção JWT/Admin é aplicada DENTRO dos endpoints específicos
app.include_router(
    users.router,
    prefix=f"{api_prefix}/users",
    tags=["Users"],
)

# --- Router de Gerenciamento ---
# Protegido GLOBALMENTE pela X-API-Key
app.include_router(
    mgmt.router,
    prefix=f"{api_prefix}/mgmt",
    tags=["Management"],
    dependencies=[
        Depends(get_api_key)
    ],  # Aplica a verificação da API Key a todas as rotas aqui
)


# Evento de shutdown para limpar a conexão com o banco
# (Nota: A warning sobre on_event é conhecida, mas funcional por enquanto)
@app.on_event("shutdown")
async def shutdown_event():
    print("Shutting down: Disposing database engine...")
    await dispose_engine()
    print("Database engine disposed.")


# Rota raiz simples
@app.get("/")
def read_root():
    return {"message": "Auth API is running!"}
