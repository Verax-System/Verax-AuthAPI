# auth_api/app/models/trusted_device.py
from sqlalchemy import String, DateTime, func, ForeignKey, Integer, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime
from typing import Optional

from app.db.base import Base
# from .user import User # Type hint import needed later

class TrustedDevice(Base):
    __tablename__ = "trusted_devices"

    id: Mapped[int] = mapped_column(primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), nullable=False)

    # Armazena o HASH do token do cookie, NUNCA o token em si
    device_token_hash: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)

    # Informações para o usuário identificar o dispositivo
    user_agent: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True) # Ex: "Chrome no Windows (Login em 2025-10-24)"

    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    user: Mapped["User"] = relationship(back_populates="trusted_devices") # type: ignore

    __table_args__ = (
        Index("ix_trusted_devices_user_id", "user_id"),
    )