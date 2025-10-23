# auth_api/app/crud/crud_user.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional, Dict, Any, List, Tuple # Importar List e Tuple
import hashlib
import secrets
from app.crud.base import CRUDBase
from app.models.user import User
from datetime import datetime, timedelta, timezone
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import ( # Importar funções OTP
    get_password_hash, verify_password, create_password_reset_token,
    verify_otp_code # Adicionar verify_otp_code
)
from app.crud import crud_refresh_token
# --- IMPORTAR O NOVO CRUD E FUNÇÕES ---
from app.crud import crud_mfa_recovery_code
# --- FIM IMPORT ---
from app.core.config import settings
from loguru import logger
from app.core.exceptions import AccountLockedException
from sqlalchemy.orm.attributes import flag_modified


class CRUDUser(CRUDBase[User, UserCreate, UserUpdate]):
    # ... (get_by_email, create, verify_user_email, authenticate, update_custom_claims) ...
    async def get_by_email(self, db: AsyncSession, *, email: str) -> Optional[User]:
        stmt = select(User).filter(User.email == email)
        result = await db.execute(stmt)
        return result.scalars().first()

    async def create(self, db: AsyncSession, *, obj_in: UserCreate) -> tuple[User, str]:
        verification_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(verification_token.encode('utf-8')).hexdigest()
        expires_delta = timedelta(minutes=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES)
        expires_at = datetime.now(timezone.utc) + expires_delta
        db_obj = User(
            email=obj_in.email,
            hashed_password=get_password_hash(obj_in.password),
            full_name=obj_in.full_name,
            is_active=False,
            is_verified=False,
            verification_token_hash=token_hash,
            verification_token_expires=expires_at.replace(tzinfo=None),
            custom_claims={}
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj, verification_token

    async def verify_user_email(self, db: AsyncSession, *, token: str) -> User | None:
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        now = datetime.now(timezone.utc).replace(tzinfo=None) # UTC naive
        stmt = select(User).where(
            User.verification_token_hash == token_hash,
            User.verification_token_expires > now,
            User.is_verified == False
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

    async def authenticate(self, db: AsyncSession, *, email: str, password: str) -> Optional[User]:
        user = await self.get_by_email(db, email=email)
        if not user: return None
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        if user.locked_until and user.locked_until > now:
            logger.warning(f"Tentativa de login para conta bloqueada: {email}")
            raise AccountLockedException(f"Account locked until {user.locked_until}", locked_until=user.locked_until)
        if not verify_password(password, user.hashed_password):
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= settings.LOGIN_MAX_FAILED_ATTEMPTS:
                lock_duration = timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
                user.locked_until = now + lock_duration
                user.failed_login_attempts = 0
                logger.warning(f"CONTA BLOQUEADA: {email} bloqueada por {lock_duration} devido a tentativas falhas.")
            db.add(user)
            await db.commit()
            return None
        if not user.is_active or not user.is_verified:
            logger.warning(f"Tentativa de login (senha correta) falhou para email não ativo/verificado: {email}")
            return None
        if user.failed_login_attempts > 0 or user.locked_until:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.add(user)
            await db.commit()
        return user

    async def update_custom_claims(self, db: AsyncSession, *, user: User, claims: Dict[str, Any]) -> User:
        if user.custom_claims:
            user.custom_claims.update(claims)
            flag_modified(user, "custom_claims")
        else:
            user.custom_claims = claims
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    # --- NOVAS FUNÇÕES CRUD MFA ---
    async def set_pending_otp_secret(self, db: AsyncSession, *, user: User, otp_secret: str) -> User:
        """Salva o segredo OTP temporariamente antes da confirmação."""
        if user.is_mfa_enabled:
             raise ValueError("MFA já está habilitado.")
        user.otp_secret = otp_secret
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    async def confirm_mfa_enable(
        self, db: AsyncSession, *, user: User, otp_code: str
    ) -> Tuple[User, List[str]] | None: # MODIFICADO: Retorna (User, List[str]) ou None
        """
        Verifica o código OTP usando o segredo PENDENTE e, se válido, 
        ativa o MFA e gera os códigos de recuperação.
        """
        if user.is_mfa_enabled or not user.otp_secret:
            logger.warning(f"Tentativa inválida de confirmar MFA para user ID {user.id}. Estado: enabled={user.is_mfa_enabled}, secret_exists={bool(user.otp_secret)}")
            return None

        if verify_otp_code(secret=user.otp_secret, code=otp_code):
            user.is_mfa_enabled = True # ATIVA O MFA
            db.add(user)
            
            # --- GERAR CÓDIGOS DE RECUPERAÇÃO ---
            # Esta função já apaga os antigos e faz commit()
            plain_recovery_codes = await crud_mfa_recovery_code.create_recovery_codes(
                db=db, user=user
            )
            # --- FIM GERAR CÓDIGOS ---
            
            # Não precisamos de db.commit() aqui pois create_recovery_codes já o fez
            await db.refresh(user)
            logger.info(f"MFA habilitado e confirmado com sucesso para usuário ID: {user.id}")
            
            # Retorna o utilizador e os códigos em texto simples
            return user, plain_recovery_codes 
        else:
            logger.warning(f"Tentativa falha de confirmar MFA para usuário ID: {user.id}. Código OTP inválido.")
            return None # Código inválido

    async def disable_mfa(self, db: AsyncSession, *, user: User, otp_code: str) -> User | None:
        """
        Verifica o código OTP atual e, se válido, desabilita o MFA 
        e apaga todos os códigos de recuperação.
        """
        if not user.is_mfa_enabled or not user.otp_secret:
            return user # Já está inativo

        if verify_otp_code(secret=user.otp_secret, code=otp_code):
            user.otp_secret = None # Remove o segredo
            user.is_mfa_enabled = False
            db.add(user)
            
            # --- APAGAR CÓDIGOS DE RECUPERAÇÃO ---
            rows_deleted = await crud_mfa_recovery_code.delete_all_codes_for_user(
                db=db, user_id=user.id
            )
            logger.info(f"MFA desabilitado. Apagados {rows_deleted} códigos de recuperação para user ID {user.id}.")
            # --- FIM APAGAR CÓDIGOS ---
            
            # delete_all_codes_for_user já fez commit
            await db.refresh(user)
            return user
        else:
            logger.warning(f"Tentativa falha de desabilitar MFA para usuário ID: {user.id}. Código OTP inválido.")
            return None # Código inválido
    # --- FIM NOVAS FUNÇÕES CRUD MFA ---

    # ... (generate_password_reset_token, get_user_by_reset_token, reset_password) ...
    async def generate_password_reset_token(self, db: AsyncSession, *, user: User) -> tuple[User, str]:
        token, expires_at = create_password_reset_token(email=user.email)
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        user.reset_password_token_hash = token_hash
        user.reset_password_token_expires = expires_at
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user, token

    async def get_user_by_reset_token(self, db: AsyncSession, *, token: str) -> User | None:
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        stmt = select(User).where(
            User.reset_password_token_hash == token_hash,
            User.reset_password_token_expires > now,
            User.is_active == True
        )
        result = await db.execute(stmt)
        return result.scalars().first()

    async def reset_password(self, db: AsyncSession, *, user: User, new_password: str) -> User:
        user.hashed_password = get_password_hash(new_password)
        user.reset_password_token_hash = None
        user.reset_password_token_expires = None
        user.failed_login_attempts = 0
        user.locked_until = None
        user.is_active = True
        db.add(user)
        revoked_count = await crud_refresh_token.revoke_all_refresh_tokens_for_user(db, user_id=user.id)
        logger.info(f"Revogados {revoked_count} refresh tokens para usuário ID {user.id} após reset de senha.")
        await db.commit()
        await db.refresh(user)
        return user

user = CRUDUser(User)