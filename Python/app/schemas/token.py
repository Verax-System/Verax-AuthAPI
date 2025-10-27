# auth_api/app/schemas/token.py
from pydantic import BaseModel
from typing import Literal, List, Optional
from datetime import datetime # <-- ADICIONAR datetime

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenPayload(BaseModel):
    sub: str | None = None
    exp: int | None = None
    token_type: str | None = None
    amr: Optional[List[str]] = None # Authentication Methods Reference

class RefreshTokenRequest(BaseModel):
    refresh_token: str

# --- Schema: Resposta MFA Obrigatório ---
class MFARequiredResponse(BaseModel):
    """Resposta indicando que a verificação MFA é necessária."""
    detail: Literal["MFA verification required"] = "MFA verification required"
    mfa_challenge_token: str # Um token temporário para a próxima etapa

# --- NOVOS SCHEMAS PARA GOOGLE OAUTH ---

class GoogleLoginUrlResponse(BaseModel):
    """Resposta que contém o URL de autorização da Google."""
    url: str

# --- ADICIONADO DE VOLTA ---
class GoogleLoginRequest(BaseModel):
    """Requisição que o frontend envia para a API com o código da Google."""
    code: str
# --- FIM ADIÇÃO ---

# --- FIM NOVOS SCHEMAS ---

class SessionInfo(BaseModel):
    """Informações sobre uma sessão de login ativa (um refresh token)."""
    id: int
    user_agent: Optional[str]
    ip_address: Optional[str]
    created_at: datetime
    expires_at: datetime

    class Config:
        from_attributes = True # Permite mapear diretamente do modelo SQLAlchemy