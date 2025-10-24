# auth_api/app/crud/crud_trusted_device.py
import secrets
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete

from app.models.user import User
from app.models.trusted_device import TrustedDevice
from app.core.config import settings
from loguru import logger

def hash_device_token(token: str) -> str:
    """Gera um hash SHA-256 para o token do dispositivo."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

async def create_trusted_device(
    db: AsyncSession,
    *,
    user: User,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None
) -> Tuple[TrustedDevice, str]:
    """
    Gera um novo token de dispositivo, guarda o seu hash e retorna o objeto DB e o token.
    """
    # 1. Gerar token seguro
    plain_token = secrets.token_urlsafe(32)
    token_hash = hash_device_token(plain_token)

    # 2. Criar descrição
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    description = f"Dispositivo reconhecido em {now_str}"
    if user_agent:
        # Tenta extrair info básica do user agent (pode precisar de uma lib mais robusta)
        ua_short = user_agent.split('(')[0].strip() if '(' in user_agent else user_agent[:50]
        description = f"{ua_short} (em {now_str})"


    # 3. Criar objeto DB
    db_device = TrustedDevice(
        user_id=user.id,
        device_token_hash=token_hash,
        ip_address=ip_address,
        user_agent=user_agent,
        description=description,
        last_used_at=datetime.now(timezone.utc).replace(tzinfo=None) # Marca como usado agora
    )

    # 4. Salvar e retornar
    db.add(db_device)
    await db.commit()
    await db.refresh(db_device)
    logger.info(f"Novo dispositivo confiável (ID: {db_device.id}) criado para user ID {user.id}")

    return db_device, plain_token

async def get_trusted_device_by_token(db: AsyncSession, *, plain_token: str) -> Optional[TrustedDevice]:
    """Encontra um dispositivo confiável pelo seu token (comparando hashes)."""
    if not plain_token:
        return None
    token_hash = hash_device_token(plain_token)

    stmt = select(TrustedDevice).where(TrustedDevice.device_token_hash == token_hash)
    result = await db.execute(stmt)
    device = result.scalars().first()

    # Atualiza last_used_at se encontrado
    if device:
        device.last_used_at = datetime.now(timezone.utc).replace(tzinfo=None)
        db.add(device)
        await db.commit()
        await db.refresh(device)

    return device

async def get_trusted_devices_for_user(db: AsyncSession, *, user_id: int) -> List[TrustedDevice]:
    """Retorna todos os dispositivos confiáveis de um usuário."""
    stmt = select(TrustedDevice).where(TrustedDevice.user_id == user_id).order_by(TrustedDevice.last_used_at.desc())
    result = await db.execute(stmt)
    return result.scalars().all()

async def delete_trusted_device(db: AsyncSession, *, db_device: TrustedDevice) -> None:
    """Remove um dispositivo confiável específico."""
    await db.delete(db_device)
    await db.commit()
    logger.info(f"Dispositivo confiável (ID: {db_device.id}) removido para user ID {db_device.user_id}")

async def get_trusted_device_by_id(db: AsyncSession, *, device_id: int, user_id: int) -> Optional[TrustedDevice]:
    """Busca um dispositivo pelo seu ID, garantindo que pertença ao usuário correto."""
    stmt = select(TrustedDevice).where(
        TrustedDevice.id == device_id,
        TrustedDevice.user_id == user_id
    )
    result = await db.execute(stmt)
    return result.scalars().first()