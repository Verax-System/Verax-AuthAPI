# auth_api/app/core/config.py
import os
import logging
from pydantic_settings import BaseSettings
from pydantic import EmailStr
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent
ENV_FILE_PATH = BASE_DIR / ".env"

class Settings(BaseSettings):

    # Core
    DATABASE_URL: str
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # Refresh Token
    REFRESH_SECRET_KEY: str
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Email (Brevo)
    BREVO_API_KEY: str
    EMAIL_FROM: EmailStr
    EMAIL_FROM_NAME: str | None = "Verax" # Manteve 'Verax' do seu código original

    # Email Links
    VERIFICATION_URL_BASE: str = "http://localhost:8000/verify" # Manteve do seu código original
    EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES: int = 60

    # Password Reset
    RESET_PASSWORD_SECRET_KEY: str | None = None
    RESET_PASSWORD_TOKEN_EXPIRE_MINUTES: int = 30
    RESET_PASSWORD_URL_BASE: str = "http://localhost:8000/reset-password" # Manteve do seu código original

    # Account Lockout
    LOGIN_MAX_FAILED_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # Chave de API Interna
    INTERNAL_API_KEY: str

    # OIDC JWT Claims (API como Recurso / IdP)
    # Issuer deve ser a URL base da SUA API
    JWT_ISSUER: str = "http://localhost:8001" # Ajustado para o valor padrão recomendado
    # Audience padrão para tokens emitidos para clientes (pode ser sobrescrito)
    JWT_AUDIENCE: str = "your-client-app-id" # Ajustado para um placeholder mais claro

    # Google OAuth2
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    GOOGLE_REDIRECT_URI_FRONTEND: str = "http://localhost:3000/google-callback" # Manteve do seu código original
    GOOGLE_REDIRECT_URI_BACKEND: str = "http://localhost:8001/api/v1/auth/google/callback" # Manteve do seu código original

    # Device Trust
    TRUSTED_DEVICE_COOKIE_NAME: str = "auth_device_id"
    TRUSTED_DEVICE_COOKIE_MAX_AGE_DAYS: int = 30

    # --- OIDC JWK Keys ---
    # Estas linhas leem as variáveis do .env
    OIDC_PRIVATE_JWK_JSON: str
    OIDC_PUBLIC_JWK_SET_JSON: str
    # --- Fim OIDC JWK Keys ---

    class Config:
        case_sensitive = True
        env_file = ENV_FILE_PATH
        env_file_encoding = 'utf-8'

try:
    # AQUI é onde o settings é criado e exportado
    settings = Settings()

    # Verificação adicional para o JWT_ISSUER (importante para OIDC)
    if not settings.JWT_ISSUER or not settings.JWT_ISSUER.startswith("http"):
        logging.warning(
            f"JWT_ISSUER ('{settings.JWT_ISSUER}') não parece ser uma URL válida. "
            f"Para OIDC funcionar corretamente, defina JWT_ISSUER no .env com a URL base da sua API (ex: http://localhost:8001)"
        )

except Exception as e:
    logging.error(f"FATAL: Erro ao carregar 'settings' a partir do .env em {ENV_FILE_PATH}: {e}")
    # Se der erro aqui, o 'settings' não será criado, causando o ImportError
    raise e