# auth_api/app/crud/crud_mfa_recovery_code.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete, Result  # Importar Result para type hint
from typing import List, Optional
import secrets

from app.models.user import User
from app.models.mfa_recovery_code import MFARecoveryCode
from app.core.security import (
    get_password_hash,  # Reutilizamos o hash de senha
    verify_password,  # Reutilizamos a verificação de senha
)
from loguru import logger

NUMBER_OF_RECOVERY_CODES = 10
RECOVERY_CODE_LENGTH = 3


def generate_plain_recovery_codes() -> List[str]:
    """Gera uma lista de códigos de recuperação legíveis."""
    codes = []
    for _ in range(NUMBER_OF_RECOVERY_CODES):
        code = f"{secrets.token_hex(RECOVERY_CODE_LENGTH)}-{secrets.token_hex(RECOVERY_CODE_LENGTH)}"
        codes.append(code)
    return codes


async def create_recovery_codes(db: AsyncSession, *, user: User) -> List[str]:
    """
    Apaga códigos antigos, gera novos códigos, guarda hashes e retorna plain codes.
    """
    await delete_all_codes_for_user(db, user_id=user.id)
    plain_codes = generate_plain_recovery_codes()

    db_codes = []
    for code in plain_codes:
        hashed_code = get_password_hash(code)
        db_codes.append(
            MFARecoveryCode(user_id=user.id, hashed_code=hashed_code, is_used=False)
        )

    db.add_all(db_codes)
    await db.commit()

    logger.info(
        f"Gerados {len(plain_codes)} novos códigos de recuperação para o user ID {user.id}"
    )
    return plain_codes


async def delete_all_codes_for_user(db: AsyncSession, *, user_id: int) -> int:
    """Apaga todos os códigos de recuperação de um utilizador."""
    stmt = delete(MFARecoveryCode).where(MFARecoveryCode.user_id == user_id)
    result: Result = await db.execute(stmt)  # Adicionar type hint para Result
    await db.commit()
    # CORRIGIDO: Acessar rowcount
    row_count = result.rowcount # type: ignore [attr-defined]
    return row_count if row_count is not None else 0  # rowcount pode ser None


async def get_valid_recovery_code(
    db: AsyncSession, *, user: User, plain_code: str
) -> Optional[MFARecoveryCode]:
    """
    Encontra um código de recuperação válido e não utilizado.
    """
    stmt = select(MFARecoveryCode).where(
        MFARecoveryCode.user_id == user.id,
        not MFARecoveryCode.is_used.is_(False),  # <-- CORRIGIDO E712 (para ruff)
    )
    result = await db.execute(stmt)
    unused_codes = result.scalars().all()

    for db_code in unused_codes:
        if verify_password(plain_code, db_code.hashed_code):
            return db_code

    return None


async def mark_code_as_used(
    db: AsyncSession, *, db_code: MFARecoveryCode
) -> MFARecoveryCode:  # <-- CORRIGIDO: Retornar o objeto atualizado
    """Marca um código de recuperação específico como utilizado."""
    db_code.is_used = True
    db.add(db_code)
    await db.commit()
    await db.refresh(db_code)
    return db_code  # <-- CORRIGIDO: Retornar o db_code atualizado
