# auth_api/main.py
from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
# --- Imports de Segurança ---
# IMPORTAR HTTPBearer
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader, HTTPBearer
# --- Fim Imports ---

# --- Adicionar imports do slowapi ---
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
# --- Fim imports slowapi ---
from app.db.session import dispose_engine
# Importar routers
from app.api.endpoints import auth, users, mgmt
# Importar dependência de chave de API E OS NOVOS ESQUEMAS
from app.api.dependencies import get_api_key, oauth2_scheme, bearer_scheme, api_key_scheme

# Importar modelos para Alembic/Base.metadata
from app.db.base import Base # noqa
from app.models import user, refresh_token # noqa

# --- REMOVER DEFINIÇÕES DE ESQUEMAS DAQUI ---
# Elas agora são importadas de 'dependencies.py'
# oauth2_scheme = ... (REMOVER)
# api_key_scheme = ... (REMOVER)
# --- FIM REMOÇÃO ---


limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])

app = FastAPI(
    title="Auth API",
    description="API Centralizada de Autenticação",
    version="1.0.0",
    # --- Adicionar/Atualizar OpenAPI security schemes ---
    # Isso informa explicitamente ao Swagger UI sobre os métodos de autenticação
    openapi_components={
        "securitySchemes": {
            # 1. Para o /token (fluxo de senha)
            "OAuth2PasswordBearer": oauth2_scheme, 
            # 2. NOVO: Para os endpoints com cadeado (colar o token)
            "BearerAuth": bearer_scheme,
            # 3. Para o /mgmt
            "APIKeyHeader": api_key_scheme        
        }
    }
    # --- Fim OpenAPI ---
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

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
# Alguns endpoints são públicos (/token, /verify-email, etc.)
# Outros requerem Bearer token (/me, /mfa/...)
# Adicionamos a dependência global do oauth2_scheme aqui, mas endpoints específicos
# como /token não o usarão diretamente. A proteção real vem das dependências
# como get_current_active_user dentro dos endpoints.
app.include_router(
    auth.router,
    prefix=f"{api_prefix}/auth",
    tags=["Authentication"],
    # REMOVA a dependência do router
    # dependencies=[Depends(oauth2_scheme)] # <-- REMOVA ESTA LINHA
)

# --- Router de Usuários ---
# POST / é público, mas GET /, GET /{id}, PUT /me requerem autenticação.
# GET / e GET /{id} também requerem admin (verificado dentro do endpoint).
app.include_router(
    users.router,
    prefix=f"{api_prefix}/users",
    tags=["Users"],
    # REMOVA a dependência do router
    # dependencies=[Depends(oauth2_scheme)] # <-- REMOVA ESTA LINHA
)

# --- Router de Gerenciamento ---
# Protegido APENAS pela chave de API
app.include_router(
    mgmt.router,
    prefix=f"{api_prefix}/mgmt",
    tags=["Management"],
    # A dependência get_api_key já usa o api_key_scheme internamente
    dependencies=[Depends(get_api_key)],
    # NÃO associar ao oauth2_scheme aqui
)


@app.on_event("shutdown")
async def shutdown_event():
    print("Shutting down: Disposing database engine...")
    await dispose_engine()
    print("Database engine disposed.")

@app.get("/")
def read_root():
    return {"message": "Auth API is running!"}