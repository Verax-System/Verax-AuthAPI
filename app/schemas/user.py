# auth_api/app/schemas/user.py
from pydantic import (
    BaseModel,
    EmailStr,
    Field,
    field_validator,
)  # <-- validator REMOVIDO

# from pydantic import validator # <-- REMOVIDO F401
from typing import Optional, Dict, Any, List  # Importar List
from datetime import datetime
import re


# Função de validação de senha
def password_strength_validator(password: str) -> str:
    if len(password) < 8:
        raise ValueError("A senha deve ter pelo menos 8 caracteres")
    if not re.search(r"[a-z]", password):
        raise ValueError("A senha deve conter pelo menos uma letra minúscula")
    if not re.search(r"[A-Z]", password):
        raise ValueError("A senha deve conter pelo menos uma letra maiúscula")
    if not re.search(r"[0-9]", password):
        raise ValueError("A senha deve conter pelo menos um número")
    if not re.search(r"[\W_]", password):  # \W corresponde a não-alfanumérico
        raise ValueError("A senha deve conter pelo menos um caractere especial")
    return password


class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None
    is_active: Optional[bool] = True


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return password_strength_validator(v)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    full_name: Optional[str] = None
    password: Optional[str] = Field(None, min_length=8)
    is_active: Optional[bool] = None

    @field_validator("password")
    @classmethod
    def validate_update_password_strength(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            return password_strength_validator(v)
        return v


class User(UserBase):
    id: int
    created_at: datetime
    updated_at: datetime
    custom_claims: Optional[Dict[str, Any]] = None
    is_mfa_enabled: bool
    is_verified: bool  # <-- ADICIONE ESTA LINHA

    class Config:
        from_attributes = True


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        return password_strength_validator(v)


# --- NOVOS SCHEMAS MFA ---


class MFAEnableResponse(BaseModel):
    """Resposta ao iniciar a habilitação do MFA."""

    # otp_secret: str # REMOVIDO por segurança - será guardado temporariamente
    otp_uri: str  # A URI para gerar o QR Code
    qr_code_base64: str  # A imagem do QR Code em base64


class MFAConfirmRequest(BaseModel):
    """Requisição para confirmar a habilitação do MFA."""

    otp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")
    # O segredo não é mais enviado pelo cliente


# --- NOVO SCHEMA DE RESPOSTA ---
class MFAConfirmResponse(BaseModel):
    """Resposta ao confirmar MFA com sucesso. Inclui os códigos de recuperação."""

    user: User
    recovery_codes: List[str] = Field(
        ..., description="Guarde estes códigos! Esta é a única vez que serão mostrados."
    )


# --- FIM NOVO SCHEMA ---


class MFADisableRequest(BaseModel):
    """Requisição para desabilitar o MFA."""

    otp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class MFAVerifyRequest(BaseModel):
    """Requisição para verificar o código MFA durante o login."""

    mfa_challenge_token: str  # Token temporário recebido na etapa anterior
    otp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


# --- NOVO SCHEMA DE REQUISIÇÃO ---
class MFARecoveryRequest(BaseModel):
    """Requisição para usar um código de recuperação durante o login."""

    mfa_challenge_token: str  # Token temporário recebido na etapa anterior
    recovery_code: str = Field(
        ..., description="Um dos códigos de recuperação de uso único (ex: abc-123)"
    )


# --- FIM NOVO SCHEMA ---

# --- FIM NOVOS SCHEMAS MFA ---
