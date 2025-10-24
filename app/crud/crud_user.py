# auth_api/app/crud/crud_user.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional, Dict, Any, List, Tuple, TypeVar, Union # Added TypeVar, Union
from pydantic import BaseModel # Added BaseModel
from fastapi.encoders import jsonable_encoder # Added jsonable_encoder
import hashlib
import secrets
from app.crud.base import CRUDBase, ModelType # Adjusted import
from app.models.user import User
from datetime import datetime, timedelta, timezone
from app.schemas.user import UserCreate, UserUpdate
from app.core.security import (
    get_password_hash, verify_password, create_password_reset_token,
    verify_otp_code
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
        self, db: AsyncSession, *, email: str, full_name: Optional[str] = None # Made full_name optional
    ) -> User:
        """
        Procura um utilizador por email. Se existir, retorna-o.
        Se não existir, cria um novo utilizador (verificado e ativo) sem password,
        destinado a logins OAuth.
        """
        user = await self.get_by_email(db, email=email)

        # Se o utilizador já existe
        if user:
            # Opcional: Atualizar o nome se estiver vazio e um novo nome foi fornecido
            if not user.full_name and full_name:
                user.full_name = full_name
                db.add(user)
                # Commit aqui é seguro pois apenas atualiza um campo opcional se necessário
                await db.commit()
                await db.refresh(user)
            return user

        # Se o utilizador não existe, criar um novo
        logger.info(f"Criando novo utilizador via OAuth para: {email}")
        db_obj = User(
            email=email,
            full_name=full_name,
            hashed_password=None, # Sem password
            is_active=True,       # Ativo por defeito
            is_verified=True,     # Verificado (confiamos no provedor OAuth)
            custom_claims={}
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj

    async def create(self, db: AsyncSession, *, obj_in: UserCreate) -> tuple[User, str]:
        """
        Cria um novo usuário com senha hashada e token de verificação.
        Retorna o objeto User e o token de verificação em texto plano.
        """
        verification_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(verification_token.encode('utf-8')).hexdigest()
        expires_delta = timedelta(minutes=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_MINUTES)
        # Use timezone-aware datetime for calculation, then make naive for DB if needed
        expires_at_aware = datetime.now(timezone.utc) + expires_delta
        expires_at_naive = expires_at_aware.replace(tzinfo=None)

        db_obj = User(
            email=obj_in.email,
            hashed_password=get_password_hash(obj_in.password),
            full_name=obj_in.full_name,
            is_active=False, # Começa inativo
            is_verified=False, # Começa não verificado
            verification_token_hash=token_hash,
            verification_token_expires=expires_at_naive, # Salva como naive
            custom_claims={}
        )
        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj, verification_token # Retorna token plano

    async def verify_user_email(self, db: AsyncSession, *, token: str) -> User | None:
        """
        Verifica um usuário usando o token de verificação de email.
        """
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None) # Comparação naive
        stmt = select(User).where(
            User.verification_token_hash == token_hash,
            User.verification_token_expires > now_naive,
            User.is_verified == False
        )
        result = await db.execute(stmt)
        user = result.scalars().first()
        if user:
            user.is_active = True
            user.is_verified = True
            user.verification_token_hash = None # Limpar token
            user.verification_token_expires = None # Limpar expiração
            db.add(user)
            await db.commit()
            await db.refresh(user)
            return user
        return None

    async def authenticate(self, db: AsyncSession, *, email: str, password: str) -> Optional[User]:
        """
        Autentica um usuário por email e senha, lidando com bloqueio de conta.
        """
        user = await self.get_by_email(db, email=email)
        if not user:
            return None

        # Impedir login com senha para contas OAuth (sem hash)
        if not user.hashed_password:
            logger.warning(f"Tentativa de login com senha para conta OAuth (sem senha): {email}")
            return None

        now_naive = datetime.now(timezone.utc).replace(tzinfo=None) # Comparação naive

        # Verificar bloqueio de conta
        if user.locked_until and user.locked_until > now_naive:
            logger.warning(f"Tentativa de login para conta bloqueada: {email} até {user.locked_until}")
            raise AccountLockedException(f"Account locked until {user.locked_until}", locked_until=user.locked_until)

        # Verificar senha
        if not verify_password(password, user.hashed_password):
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1 # Garantir que não é None
            if user.failed_login_attempts >= settings.LOGIN_MAX_FAILED_ATTEMPTS:
                lock_duration = timedelta(minutes=settings.LOGIN_LOCKOUT_MINUTES)
                user.locked_until = now_naive + lock_duration
                # Resetar tentativas APÓS o bloqueio ser definido
                user.failed_login_attempts = 0
                logger.warning(f"CONTA BLOQUEADA: {email} bloqueada por {lock_duration} devido a {settings.LOGIN_MAX_FAILED_ATTEMPTS} tentativas falhas.")
            else:
                 logger.warning(f"Senha incorreta para {email}. Tentativa {user.failed_login_attempts}/{settings.LOGIN_MAX_FAILED_ATTEMPTS}.")

            db.add(user)
            await db.commit()
            return None # Senha incorreta

        # Verificar se a conta está ativa e verificada
        if not user.is_active or not user.is_verified:
            logger.warning(f"Tentativa de login (senha correta) falhou para email não ativo/verificado: {email}")
            return None

        # Resetar contador de falhas e bloqueio em caso de login bem-sucedido
        if user.failed_login_attempts > 0 or user.locked_until:
            user.failed_login_attempts = 0
            user.locked_until = None
            db.add(user)
            await db.commit()
            # Refresh pode ser útil aqui se o objeto for usado imediatamente depois
            # await db.refresh(user)

        return user

    # --- MÉTODO UPDATE CORRIGIDO ---
    async def update(
        self,
        db: AsyncSession,
        *,
        db_obj: User, # Explicitamente User
        obj_in: Union[UserUpdate, Dict[str, Any]]
    ) -> User:
        obj_data = jsonable_encoder(db_obj) # Obter dados atuais do objeto DB
        if isinstance(obj_in, dict):
            update_data = obj_in
        else:
            # exclude_unset=True é crucial para atualizações parciais
            update_data = obj_in.model_dump(exclude_unset=True)

        # Iterar sobre os campos PRESENTES no update_data
        for field, value in update_data.items():
            if field == "password":
                # Tratamento especial para o campo 'password'
                if value: # Somente hash e atualiza se uma nova senha foi fornecida
                    hashed_password = get_password_hash(value)
                    setattr(db_obj, "hashed_password", hashed_password)
                    logger.debug(f"Atualizando hashed_password para user ID {db_obj.id}")
            elif hasattr(db_obj, field):
                 # Atualizar outros campos diretamente
                 setattr(db_obj, field, value)

        # Marcar custom_claims se foi modificado (necessário para JSON)
        if "custom_claims" in update_data:
             flag_modified(db_obj, "custom_claims")

        db.add(db_obj)
        await db.commit()
        await db.refresh(db_obj)
        return db_obj
    # --- FIM MÉTODO UPDATE CORRIGIDO ---

    async def update_custom_claims(self, db: AsyncSession, *, user: User, claims: Dict[str, Any]) -> User:
        """Mescla os claims fornecidos com os claims existentes do usuário."""
        if user.custom_claims:
            # Faz merge, onde os novos 'claims' sobrescrevem chaves existentes
            user.custom_claims.update(claims)
        else:
            user.custom_claims = claims
        # Sinaliza para o SQLAlchemy que o campo JSON foi modificado
        flag_modified(user, "custom_claims")
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user

    async def set_pending_otp_secret(self, db: AsyncSession, *, user: User, otp_secret: str) -> User:
        """Define o segredo OTP pendente para habilitação de MFA."""
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
        """Confirma a habilitação do MFA verificando o código OTP e gera códigos de recuperação."""
        if user.is_mfa_enabled or not user.otp_secret:
            logger.warning(f"Tentativa inválida de confirmar MFA para user ID {user.id}. Estado: enabled={user.is_mfa_enabled}, secret_exists={bool(user.otp_secret)}")
            return None

        if verify_otp_code(secret=user.otp_secret, code=otp_code):
            user.is_mfa_enabled = True
            db.add(user) # Adiciona a mudança user.is_mfa_enabled = True

            # create_recovery_codes APAGA os antigos e ADICIONA os novos (sem commit)
            plain_recovery_codes = await crud_mfa_recovery_code.create_recovery_codes(
                db=db, user=user
            )

            # Commit único para salvar user.is_mfa_enabled e os novos recovery codes
            try:
                await db.commit()
            except Exception as e:
                logger.error(f"Erro ao commitar confirmação de MFA para user ID {user.id}: {e}")
                await db.rollback()
                # Não limpar o otp_secret aqui, permitir nova tentativa de confirmação
                return None

            await db.refresh(user) # Atualiza o objeto user com o estado do DB
            logger.info(f"MFA habilitado e confirmado com sucesso para usuário ID: {user.id}")

            return user, plain_recovery_codes
        else:
            logger.warning(f"Tentativa falha de confirmar MFA para usuário ID: {user.id}. Código OTP inválido.")
            # Não fazer rollback aqui, o estado não mudou no DB
            return None

    async def disable_mfa(self, db: AsyncSession, *, user: User, otp_code: str) -> User | None:
        """Desabilita o MFA verificando o código OTP e remove códigos de recuperação."""
        if not user.is_mfa_enabled or not user.otp_secret:
            # MFA já desabilitado ou sem segredo, não faz nada
            return user

        if verify_otp_code(secret=user.otp_secret, code=otp_code):
            user.otp_secret = None # Limpa o segredo
            user.is_mfa_enabled = False
            db.add(user) # Adiciona a mudança user.is_mfa_enabled = False

            # delete_all_codes_for_user APAGA os códigos (sem commit)
            rows_deleted = await crud_mfa_recovery_code.delete_all_codes_for_user(
                db=db, user_id=user.id
            )

            # Commit único para salvar user.is_mfa_enabled = False e a remoção dos códigos
            try:
                await db.commit()
                logger.info(f"MFA desabilitado. Apagados {rows_deleted} códigos de recuperação para user ID {user.id}.")
            except Exception as e:
                 logger.error(f"Erro ao commitar desabilitação de MFA para user ID {user.id}: {e}")
                 await db.rollback()
                 # Reverter as alterações no objeto user se o commit falhar? Opcional.
                 # user.otp_secret = original_secret # Precisaria guardar o original
                 # user.is_mfa_enabled = True
                 return None # Indicar falha

            await db.refresh(user)
            return user
        else:
            logger.warning(f"Tentativa falha de desabilitar MFA para usuário ID: {user.id}. Código OTP inválido.")
            return None

    async def generate_password_reset_token(self, db: AsyncSession, *, user: User) -> tuple[User, str]:
        """Gera um token de reset de senha para o usuário."""
        token, expires_at_aware = create_password_reset_token(email=user.email)
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        user.reset_password_token_hash = token_hash
        user.reset_password_token_expires = expires_at_aware.replace(tzinfo=None) # Salvar naive
        db.add(user)
        await db.commit()
        await db.refresh(user)
        return user, token # Retorna token plano

    async def get_user_by_reset_token(self, db: AsyncSession, *, token: str) -> User | None:
        """Busca um usuário ativo pelo token de reset de senha."""
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        now_naive = datetime.now(timezone.utc).replace(tzinfo=None) # Comparação naive
        stmt = select(User).where(
            User.reset_password_token_hash == token_hash,
            User.reset_password_token_expires > now_naive,
            User.is_active == True # Somente usuários ativos podem resetar
        )
        result = await db.execute(stmt)
        return result.scalars().first()

    async def reset_password(self, db: AsyncSession, *, user: User, new_password: str) -> User:
        """Define uma nova senha para o usuário e limpa o token de reset."""
        user.hashed_password = get_password_hash(new_password)
        user.reset_password_token_hash = None
        user.reset_password_token_expires = None
        user.failed_login_attempts = 0 # Resetar contador de falhas
        user.locked_until = None # Desbloquear conta
        user.is_active = True # Garantir que está ativo (caso tenha sido desativado)
        db.add(user)

        # Revogar todos os refresh tokens existentes para segurança
        revoked_count = await crud_refresh_token.revoke_all_refresh_tokens_for_user(db, user_id=user.id)
        logger.info(f"Revogados {revoked_count} refresh tokens para usuário ID {user.id} após reset de senha.")

        await db.commit() # Salva a nova senha E a revogação dos tokens
        await db.refresh(user)
        return user

# Instância única do CRUD para ser usada nos endpoints
user = CRUDUser(User)