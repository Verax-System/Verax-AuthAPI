# auth_api/app/models/refresh_token.py
from sqlalchemy import String, DateTime, func, ForeignKey, Integer, Boolean, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from typing import Optional # <-- ADICIONAR Optional

from app.db.base import Base
from .user import User # Importa o modelo User

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    
    # --- NOVAS COLUNAS ---
    ip_address: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    # --- FIM NOVAS COLUNAS ---

    user: Mapped["User"] = relationship()

    __table_args__ = (Index("ix_refresh_tokens_user_hash", "user_id", "token_hash"),)