# auth_api/app/crud/crud_mfa_recovery_code.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import delete
from typing import List, Optional
import secrets

from app.models.user import User
from app.models.mfa_recovery_code import MFARecoveryCode
from app.core.security import (
    get_password_hash, # Reutilizamos o hash de senha
    verify_password # Reutilizamos a verificação de senha
)
from loguru import logger

# Quantos códigos gerar
NUMBER_OF_RECOVERY_CODES = 10
# Formato do código (ex: abc-123)
RECOVERY_CODE_LENGTH = 3

def generate_plain_recovery_codes() -> List[str]:
    """Gera uma lista de códigos de recuperação legíveis."""
    codes = []
    for _ in range(NUMBER_OF_RECOVERY_CODES):
        # Gera códigos no formato "abc-def"
        code = f"{secrets.token_hex(RECOVERY_CODE_LENGTH)}-{secrets.token_hex(RECOVERY_CODE_LENGTH)}"
        codes.append(code)
    return codes

async def create_recovery_codes(
    db: AsyncSession, *, user: User
) -> List[str]:
    """
    Apaga códigos antigos, gera novos códigos de recuperação,
    guarda os seus hashes e retorna os códigos em texto simples.
    """
    # 1. Apagar todos os códigos antigos
    await delete_all_codes_for_user(db, user_id=user.id)

    # 2. Gerar novos códigos em texto simples
    plain_codes = generate_plain_recovery_codes()

    # 3. Criar os objetos do modelo com os hashes
    db_codes = []
    for code in plain_codes:
        hashed_code = get_password_hash(code) # Usar o mesmo hash da senha
        db_codes.append(
            MFARecoveryCode(
                user_id=user.id,
                hashed_code=hashed_code,
                is_used=False
            )
        )

    # 4. Adicionar à sessão e fazer commit
    db.add_all(db_codes)
    await db.commit()

    logger.info(f"Gerados {len(plain_codes)} novos códigos de recuperação para o user ID {user.id}")

    # 5. Retornar os códigos em texto simples (para mostrar ao utilizador)
    return plain_codes

async def delete_all_codes_for_user(db: AsyncSession, *, user_id: int) -> int:
    """Apaga todos os códigos de recuperação de um utilizador (ex: ao desativar MFA)."""
    stmt = delete(MFARecoveryCode).where(MFARecoveryCode.user_id == user_id)
    result = await db.execute(stmt)
    # Não precisa de commit() aqui se for chamado por outra função que faz commit
    # Mas se for chamado sozinho, precisa. Adicionamos por segurança.
    await db.commit()
    return result.rowcount

async def get_valid_recovery_code(
    db: AsyncSession, *, user: User, plain_code: str
) -> Optional[MFARecoveryCode]:
    """
    Encontra um código de recuperação válido e não utilizado para um utilizador.
    """
    # 1. Buscar TODOS os códigos não utilizados do utilizador
    # (Não podemos fazer query pelo hash, pois o plain_code não gera o mesmo hash sempre)
    stmt = select(MFARecoveryCode).where(
        MFARecoveryCode.user_id == user.id,
        not MFARecoveryCode.is_used # <-- CORRIGIDO E712
    )
    result = await db.execute(stmt)
    unused_codes = result.scalars().all()

    # 2. Iterar e verificar o hash de cada um
    for db_code in unused_codes:
        # Usar a mesma verificação da senha
        if verify_password(plain_code, db_code.hashed_code):
            return db_code # Encontrado!

    # 3. Se o loop terminar, nenhum código válido foi encontrado
    return None

async def mark_code_as_used(
    db: AsyncSession, *, db_code: MFARecoveryCode
) -> MFARecoveryCode:
    """Marca um código de recuperação específico como utilizado."""
    db_code.is_used = True
    db.add(db_code)
    await db.commit()
    await db.refresh(db_code)
    return db_code