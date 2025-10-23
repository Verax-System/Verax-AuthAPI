# auth_api/app/models/mfa_recovery_code.py
from sqlalchemy import String, ForeignKey, Boolean, Index
# from sqlalchemy import Integer # <-- REMOVIDO F401
from sqlalchemy.orm import Mapped, mapped_column, relationship
# from datetime import datetime # <-- REMOVIDO F401
from typing import TYPE_CHECKING # <-- Adicionado para type hint

from app.db.base import Base

# Adicionado para evitar import circular para type hints
if TYPE_CHECKING:
    from .user import User # noqa F401

class MFARecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    # Armazena o HASH do código, NUNCA o código em si
    hashed_code: Mapped[str] = mapped_column(String(255), nullable=False)

    # Marca se o código já foi utilizado
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # <-- Corrigido F821 (com TYPE_CHECKING)
    user: Mapped["User"] = relationship(back_populates="recovery_codes")

    __table_args__ = (
        # Índice para encontrar rapidamente códigos de um usuário
        Index("ix_mfa_recovery_codes_user_id", "user_id"),
        # Índice para garantir que hashes sejam únicos (opcional, mas bom)
        Index("ix_mfa_recovery_codes_hashed_code", "hashed_code", unique=True),
    )