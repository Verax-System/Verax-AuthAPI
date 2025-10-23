# auth_api/app/crud/crud_refresh_token.py
import hashlib
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete  # Import delete
from sqlalchemy.exc import IntegrityError  # <-- MOVIDO PARA O TOPO E402
from fastapi import HTTPException  # <-- MOVIDO PARA O TOPO E402
# from typing import Optional # <-- REMOVIDO F401

from app.models.refresh_token import RefreshToken
from app.models.user import User
from loguru import logger  # Add logger


# Função simples para gerar hash (poderia usar passlib se preferir consistência)
def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def create_refresh_token(
    db: AsyncSession, *, user: User, token: str, expires_at: datetime
) -> RefreshToken:
    """Cria e armazena o hash de um novo refresh token, removendo os antigos."""
    token_hash_value = hash_token(token)

    # --- REMOVE EXISTING TOKENS FOR USER ---
    try:
        stmt_delete = delete(RefreshToken).where(
            RefreshToken.user_id == user.id,
            # Opcional: só deletar os não revogados? Depende da sua lógica.
            # not RefreshToken.is_revoked
        )
        await db.execute(stmt_delete)  # <-- REMOVIDA VARIÁVEL 'result' F841
        # logger.info(f"Removed {result.rowcount} existing refresh token(s) for user ID {user.id}") # Optional logging
    except Exception as e:
        logger.error(f"Error removing old refresh tokens for user ID {user.id}: {e}")
        # Decide if you want to raise an error or just log and continue
        # raise HTTPException(status_code=500, detail="Could not clear old sessions.")
    # --- END REMOVAL ---

    db_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash_value,
        expires_at=expires_at,
        is_revoked=False,
    )
    db.add(db_token)

    # --- COMMIT IS CRITICAL HERE ---
    # We need to commit the delete and the insert together
    try:
        await db.commit()
        await db.refresh(db_token)
        return db_token
    except (
        IntegrityError
    ) as e:  # Catch potential race conditions if logins are extremely concurrent
        await db.rollback()
        logger.error(
            f"Integrity error creating refresh token for user ID {user.id}: {e}"
        )
        # Maybe try fetching the existing token again or raise specific error
        raise HTTPException(
            status_code=409,
            detail="Failed to create token due to conflict. Please try again.",
        )
    except Exception as e:
        await db.rollback()
        logger.error(f"Generic error creating refresh token for user ID {user.id}: {e}")
        raise HTTPException(status_code=500, detail="Could not create refresh token.")
    # --- END COMMIT ---


async def get_refresh_token(db: AsyncSession, *, token: str) -> RefreshToken | None:
    """Busca um refresh token pelo seu valor (comparando hashes)."""
    token_hash_value = hash_token(token)
    # Ensure comparison is timezone-naive if expires_at is naive
    now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)

    stmt = select(RefreshToken).where(
        RefreshToken.token_hash == token_hash_value,
        not RefreshToken.is_revoked,  # <-- CORRIGIDO E712
        RefreshToken.expires_at > now_utc_naive,  # Compare naive datetimes
    )
    result = await db.execute(stmt)
    return result.scalars().first()


async def revoke_refresh_token(db: AsyncSession, *, token: str) -> bool:
    """Marca um refresh token como revogado usando seu hash."""
    token_hash_value = hash_token(token)
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash_value)
    result = await db.execute(stmt)
    db_token = result.scalars().first()

    if db_token and not db_token.is_revoked:  # Only update if not already revoked
        db_token.is_revoked = True
        db.add(db_token)
        await db.commit()
        return True
    return False  # Return False if not found or already revoked


# ... (revoke_all_refresh_tokens_for_user and prune_expired_tokens remain the same) ...


async def revoke_all_refresh_tokens_for_user(db: AsyncSession, *, user_id: int) -> int:
    """Revoga todos os refresh tokens de um usuário (ex: ao trocar senha)."""
    stmt = select(RefreshToken).where(
        RefreshToken.user_id == user_id,
        not RefreshToken.is_revoked,  # <-- CORRIGIDO E712
    )
    result = await db.execute(stmt)
    tokens = result.scalars().all()
    count = 0
    for token in tokens:
        token.is_revoked = True
        db.add(token)
        count += 1
    if count > 0:
        await db.commit()
    return count


async def prune_expired_tokens(db: AsyncSession) -> int:
    """Remove tokens expirados do banco (pode ser rodado periodicamente)."""
    now_utc_naive = datetime.now(timezone.utc).replace(tzinfo=None)
    stmt = delete(RefreshToken).where(RefreshToken.expires_at <= now_utc_naive)
    result = await db.execute(stmt)
    await db.commit()
    return result.rowcount  # Número de linhas deletadas


# Imports movidos para o topo
