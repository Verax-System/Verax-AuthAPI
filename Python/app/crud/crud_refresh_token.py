# auth_api/app/crud/crud_refresh_token.py
import hashlib
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete, update # <-- ADICIONAR update

from app.models.refresh_token import RefreshToken
from app.models.user import User
from loguru import logger
from sqlalchemy.exc import IntegrityError
from fastapi import HTTPException
from typing import Optional, List # <-- ADICIONAR List

# (hash_token permanece o mesmo)
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()

async def create_refresh_token(
    db: AsyncSession, 
    *, 
    user: User, 
    token: str, 
    expires_at: datetime,
    ip_address: Optional[str] = None,  # <-- NOVO
    user_agent: Optional[str] = None   # <-- NOVO
) -> RefreshToken:
    """Cria e armazena o hash de um novo refresh token."""
    token_hash_value = hash_token(token)

    # --- REMOVER A LÓGICA DE APAGAR TOKENS ANTIGOS ---
    # (O bloco try/except stmt_delete foi removido daqui)
    # --- FIM DA REMOÇÃO ---

    db_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash_value,
        expires_at=expires_at,
        is_revoked=False,
        ip_address=ip_address, # <-- NOVO
        user_agent=user_agent  # <-- NOVO
    )
    db.add(db_token)

    try:
        # Commit apenas da adição do novo token
        await db.commit()
        await db.refresh(db_token)
        return db_token
    except IntegrityError as e: 
        await db.rollback()
        logger.error(f"Integrity error creating refresh token for user ID {user.id}: {e}")
        raise HTTPException(status_code=409, detail="Failed to create token due to conflict. Please try again.")
    except Exception as e:
        await db.rollback()
        logger.error(f"Generic error creating refresh token for user ID {user.id}: {e}")
        raise HTTPException(status_code=500, detail="Could not create refresh token.")


async def get_refresh_token(db: AsyncSession, *, token: str) -> RefreshToken | None:
    # (Esta função permanece a mesma)
    token_hash_value = hash_token(token)
    now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)

    stmt = select(RefreshToken).where(
        RefreshToken.token_hash == token_hash_value,
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > now_utc_naive
    )
    result = await db.execute(stmt)
    return result.scalars().first()

async def revoke_refresh_token(db: AsyncSession, *, token: str) -> bool:
    # (Esta função permanece a mesma)
    token_hash_value = hash_token(token)
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash_value)
    result = await db.execute(stmt)
    db_token = result.scalars().first()

    if db_token and not db_token.is_revoked:
        db_token.is_revoked = True
        db.add(db_token)
        await db.commit()
        return True
    return False

# --- NOVAS FUNÇÕES ---

async def get_active_sessions_for_user(db: AsyncSession, *, user_id: int) -> List[RefreshToken]:
    """Retorna todas as sessões (tokens) ativas e não expiradas de um usuário."""
    now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    
    stmt = select(RefreshToken).where(
        RefreshToken.user_id == user_id,
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > now_utc_naive
    ).order_by(RefreshToken.created_at.desc()) # Ordena pelas mais recentes
    
    result = await db.execute(stmt)
    return result.scalars().all()

async def get_refresh_token_by_id(db: AsyncSession, *, token_id: int, user_id: int) -> Optional[RefreshToken]:
    """Busca um token pelo seu ID, garantindo que pertença ao usuário correto."""
    stmt = select(RefreshToken).where(
        RefreshToken.id == token_id,
        RefreshToken.user_id == user_id
    )
    result = await db.execute(stmt)
    return result.scalars().first()

async def revoke_refresh_token_by_id(db: AsyncSession, *, db_token: RefreshToken) -> bool:
    """Marca um token específico (obtido por get_refresh_token_by_id) como revogado."""
    if db_token and not db_token.is_revoked:
        db_token.is_revoked = True
        db.add(db_token)
        await db.commit()
        return True
    return False

async def revoke_all_refresh_tokens_for_user(db: AsyncSession, *, user_id: int, exclude_token_hash: Optional[str] = None) -> int:
    """
    Revoga todos os refresh tokens de um usuário, opcionalmente excluindo
    o token da sessão atual.
    """
    now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    
    stmt = update(RefreshToken).where(
        RefreshToken.user_id == user_id,
        RefreshToken.is_revoked == False,
        RefreshToken.expires_at > now_utc_naive
    )
    
    if exclude_token_hash:
        stmt = stmt.where(RefreshToken.token_hash != exclude_token_hash)
        
    stmt = stmt.values(is_revoked=True)
    
    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount # Número de linhas afetadas


async def prune_expired_tokens(db: AsyncSession) -> int:
    # (Esta função permanece a mesma)
    now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    stmt = delete(RefreshToken).where(RefreshToken.expires_at <= now_utc_naive)
    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount