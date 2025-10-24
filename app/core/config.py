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

    # --- Configurações de Email (SendGrid) ---
    BREVO_API_KEY: str # Substitua SENDGRID_API_KEY por esta linha
    EMAIL_FROM: EmailStr
    EMAIL_FROM_NAME: str | None = "Verax AuthAPI"

    # Email Links
    VERIFICATION_URL_BASE: str = "http://localhost:8000/verify"
    EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES: int = 60

    # Password Reset
    RESET_PASSWORD_SECRET_KEY: str | None = None
    RESET_PASSWORD_TOKEN_EXPIRE_MINUTES: int = 30
    RESET_PASSWORD_URL_BASE: str = "http://localhost:8000/reset-password"

    # Account Lockout
    LOGIN_MAX_FAILED_ATTEMPTS: int = 5
    LOGIN_LOCKOUT_MINUTES: int = 15

    # Chave de API Interna
    INTERNAL_API_KEY: str

    # --- OIDC JWT Claims ---
    JWT_ISSUER: str = "urn:verax:authapi"
    JWT_AUDIENCE: str = "urn:verax:client"

    # --- Google OAuth2 ---
    GOOGLE_CLIENT_ID: str | None = None
    GOOGLE_CLIENT_SECRET: str | None = None
    # URL do SEU frontend (para produção)
    GOOGLE_REDIRECT_URI_FRONTEND: str = "http://localhost:3000/google-callback"
    # URL do backend (usado apenas para testes locais da API)
    GOOGLE_REDIRECT_URI_BACKEND: str = "http://localhost:8001/api/v1/auth/google/callback"

    class Config:
        case_sensitive = True
        env_file = ENV_FILE_PATH
        env_file_encoding = 'utf-8'

try:
    # AQUI é onde o settings é criado e exportado
    settings = Settings()
except Exception as e:
    logging.error(f"FATAL: Erro ao carregar 'settings' a partir do .env em {ENV_FILE_PATH}: {e}")
    # Se der erro aqui, o 'settings' não será criado, causando o ImportError
    raise e