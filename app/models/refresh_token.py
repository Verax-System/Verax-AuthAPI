# auth_api/app/models/refresh_token.py
from sqlalchemy import String, DateTime, func, ForeignKey, Boolean, Index
# from sqlalchemy import Integer # <-- REMOVIDO F401
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from typing import TYPE_CHECKING

from app.db.base import Base

if TYPE_CHECKING:
    from .user import User # Importa o modelo User para type hints

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)
    # Armazena um HASH do token, não o token em si, por segurança
    token_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    # JTI (JWT ID) pode ser usado para identificar o token se você usar 'jti' no payload
    # jti: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    # Opcional: revogado explicitamente (útil para logout global)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    user: Mapped["User"] = relationship()

    # Índice para buscar rapidamente tokens por usuário e hash
    __table_args__ = (Index("ix_refresh_tokens_user_hash", "user_id", "token_hash"),)