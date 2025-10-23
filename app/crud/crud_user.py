# auth_api/app/crud/crud_user.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional, Dict, Any, List, Tuple
import hashlib
import secrets
from app.crud.base import CRUDBase
from app.models.user import User
from datetime import datetime, timedelta, timezone

# from app.schemas.user import UserCreate, UserUpdate, User as UserSchema # REMOVED F401
from app.schemas.user import UserCreate, UserUpdate  # <-- REMOVED UNUSED ALIAS F401
from app.core.security import (
    get_password_hash,
    verify_password,
    create_password_reset_token,
    verify_otp_code,
)
from app.crud import crud_refresh_token
from app.crud import crud_mfa_recovery_code
from app.core.config import settings
from loguru import logger
from app.core.exceptions import AccountLockedException
from sqlalchemy.orm.attributes import flag_modified


class CRUDUser(CRUDBase[User, UserCreate, UserUpdate]):
    async def get_by_email(self, db: AsyncSession, *, email: str) -> Optional[User]:
        stmt = select(User).filter(User.email == email)
        result = await db.execute(stmt)
        return result.scalars().first()

    async def get_or_create_by_email_oauth(
        self, db: AsyncSession, *, email: str, full_name: str | None = None
    ) -> User:
        """Cria ou obtém usuário para OAuth."""
        user = await self.get_by_email(db, email=email)
        if user:
            if not user.full_name and full_name:
                user.full_name = full_name
                db.add(user)
                await db.commit()
                await db.refresh(user)
            return user

        logger.info(f"Criando novo utilizador via OAuth para: {email}")
        db_obj = User(
            email=email,
            full_name=full_name,
            hashed_password=None,
            is_active=True,
            is_verified=True,
            custom_claims={},
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def create(self, db: AsyncSession, *, obj_in: UserCreate) -> tuple[User, str]:  # type: ignore
        """Cria usuário e retorna (usuário, token_verificação)."""
        verification_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(verification_token.encode("utf-8")).hexdigest()
        expires_delta = timedelta(
            minutes=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES
        )
        expires_at = datetime.now(timezone.utc) + expires_delta
        db_obj = User(
            email=obj_in.email,
            hashed_password=get_password_hash(obj_in.password),
            full_name=obj_in.full_name,
            is_active=False,
            is_verified=False,
            verification_token_hash=token_hash,
            verification_token_expires=expires_at.replace(tzinfo=None),
            custom_claims={},
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj, verification_token

    async def verify_user_email(self, db: AsyncSession, *, token: str) -> User | None:
        """Verifica email do usuário usando token."""
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        stmt = select(User).where(
            User.verification_token_hash == token_hash,
            User.verification_token_expires > now,
            not User.is_verified.is_(False),  # <-- CORRIGIDO E712 (para ruff)
        )
        result = await db.execute(stmt)
        user = result.scalars().first()
        if user:
            user.is_active = True
            user.is_verified = True
            user.verification_token_hash = None
            user.verification_token_expires = None
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user
        return None

    async def authenticate(
        self, db: AsyncSession, *, email: str, password: str
    ) -> Optional[User]:
        """Autentica usuário, lida com lockout."""
        user = await self.get_by_email(db, email=email)
        if not user:
            return None

        if not user.hashed_password:
            logger.warning(f"Tentativa de login com senha para conta OAuth: {email}")
            return None

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if user.locked_until and user.locked_until > now:
            logger.warning(f"Tentativa de login para conta bloqueada: {email}")
            raise AccountLockedException(
                f"Account locked until {user.locked_until}",
                locked_until=user.locked_until,
            )

        if not verify_password(password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.LOGIN_MAX_FAILED_ATTEMPTS:
                lock_duration = timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
                user.locked_until = now + lock_duration
                # Não zerar tentativas aqui, apenas no login sucesso
                logger.warning(f"CONTA BLOQUEADA: {email} por {lock_duration}.")
            db.add(user)
            await db.commit()
            return None

        if not user.is_active or not user.is_verified:
            logger.warning(f"Login falhou (ativo/verificado): {email}")
            return None

        if user.failed_login_attempts > 0 or user.locked_until:
            user.failed_login_attempts = 0  # Zerar no sucesso
            user.locked_until = None
            db.add(user)
            await db.commit()
            await db.refresh(user)  # Recarregar para garantir estado atualizado

        return user

    async def update_custom_claims(
        self, db: AsyncSession, *, user: User, claims: Dict[str, Any]
    ) -> User:
        """Atualiza custom_claims do usuário."""
        if user.custom_claims:
            if not isinstance(user.custom_claims, dict):
                user.custom_claims = {}
            user.custom_claims.update(claims)
            flag_modified(user, "custom_claims")
        else:
            user.custom_claims = claims
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    async def set_pending_otp_secret(
        self, db: AsyncSession, *, user: User, otp_secret: str
    ) -> User:
        """Define segredo OTP pendente."""
        if user.is_mfa_enabled:
            raise ValueError("MFA já está habilitado.")
        user.otp_secret = otp_secret
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    async def confirm_mfa_enable(
        self, db: AsyncSession, *, user: User, otp_code: str
    ) -> Tuple[User, List[str]] | None:
        """Confirma ativação do MFA."""
        if user.is_mfa_enabled or not user.otp_secret:
            logger.warning(f"Tentativa inválida de confirmar MFA: User ID {user.id}")
            return None

        if verify_otp_code(secret=user.otp_secret, code=otp_code):
            user.is_mfa_enabled = True
            db.add(user)

            plain_recovery_codes = await crud_mfa_recovery_code.create_recovery_codes(
                db=db, user=user
            )  # Commit já é feito dentro de create_recovery_codes

            # Não precisa de commit aqui, mas refresh sim
            await db.refresh(user)
            logger.info(f"MFA habilitado: User ID {user.id}")

            return user, plain_recovery_codes
        else:
            logger.warning(f"Falha ao confirmar MFA (OTP inválido): User ID {user.id}")
            return None

    async def disable_mfa(
        self, db: AsyncSession, *, user: User, otp_code: str
    ) -> User | None:
        """Desabilita MFA."""
        if not user.is_mfa_enabled or not user.otp_secret:
            return user  # Já está desabilitado ou sem segredo

        if verify_otp_code(secret=user.otp_secret, code=otp_code):
            user.otp_secret = None
            user.is_mfa_enabled = False
            db.add(user)

            rows_deleted = await crud_mfa_recovery_code.delete_all_codes_for_user(
                db=db, user_id=user.id
            )  # Commit já é feito dentro
            logger.info(
                f"MFA desabilitado. Apagados {rows_deleted} códigos: User ID {user.id}"
            )

            # Commit final para user.is_mfa_enabled e otp_secret = None
            await db.commit()
            await db.refresh(user)
            return user
        else:
            logger.warning(
                f"Falha ao desabilitar MFA (OTP inválido): User ID {user.id}"
            )
            return None

    async def generate_password_reset_token(
        self, db: AsyncSession, *, user: User
    ) -> tuple[User, str]:
        """Gera token de reset de senha."""
        token, expires_at = create_password_reset_token(email=user.email)
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        user.reset_password_token_hash = token_hash
        user.reset_password_token_expires = expires_at
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user, token

    async def get_user_by_reset_token(
        self, db: AsyncSession, *, token: str
    ) -> User | None:
        """Busca usuário por token de reset válido."""
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        stmt = select(User).where(
            User.reset_password_token_hash == token_hash,
            User.reset_password_token_expires > now,
            User.is_active,  # <-- CORRIGIDO E712 (para ruff)
        )
        result = await db.execute(stmt)
        return result.scalars().first()

    async def reset_password(
        self, db: AsyncSession, *, user: User, new_password: str
    ) -> User:
        """Redefine a senha do usuário e revoga tokens."""
        user.hashed_password = get_password_hash(new_password)
        user.reset_password_token_hash = None
        user.reset_password_token_expires = None
        user.failed_login_attempts = 0
        user.locked_until = None
        user.is_active = True
        db.add(user)
        # Revogar tokens ANTES do commit final da senha
        revoked_count = await crud_refresh_token.revoke_all_refresh_tokens_for_user(
            db, user_id=user.id
        )
        logger.info(f"Revogados {revoked_count} tokens: User ID {user.id}")
        await db.commit()  # Commit da nova senha e revogação
        await db.refresh(user)
        return user


user = CRUDUser(User)
