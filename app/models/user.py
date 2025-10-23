# auth_api/app/models/user.py
from sqlalchemy import String, DateTime, func, Boolean, Integer, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from typing import Optional, List

from app.db.base import Base
from app.models.mfa_recovery_code import MFARecoveryCode  # type: ignore


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    email: Mapped[str] = mapped_column(
        String(100), unique=True, index=True, nullable=False
    )

    # --- MODIFICAÇÃO CRÍTICA ---
    # Tem de ser opcional (nullable=True) para permitir logins OAuth
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # --- FIM MODIFICAÇÃO ---

    full_name: Mapped[Optional[str]] = mapped_column(String(150))
    is_active: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # --- Campos Verificação ---
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_token_hash: Mapped[Optional[str]] = mapped_column(
        String(255), index=True
    )
    verification_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime)
    # --- Fim Campos Verificação ---
    reset_password_token_hash: Mapped[Optional[str]] = mapped_column(
        String(255), index=True
    )
    reset_password_token_expires: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # --- Campos: Account Lockout (EXISTENTES) ---
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # --- Fim Campos Lockout ---

    # --- Campo Custom Claims (EXISTENTE) ---
    custom_claims: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # --- Fim Custom Claims ---

    # --- CAMPOS: MFA/2FA ---
    otp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    is_mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False, server_default="false"
    )
    # --- FIM NOVOS CAMPOS ---

    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), onupdate=func.now()
    )

    # --- RELAÇÃO (EXISTENTE) ---
    recovery_codes: Mapped[List["MFARecoveryCode"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    # --- FIM RELAÇÃO ---
