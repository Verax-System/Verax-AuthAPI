# auth_api/app/api/endpoints/auth.py
from loguru import logger
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Union
from app.crud import crud_refresh_token
from fastapi import APIRouter, Depends, HTTPException, status, Response
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.dependencies import get_current_active_user, get_db
from app.crud.crud_user import user as crud_user
from app.db.session import get_db
from app.core import security
from app.core.config import settings
from app.schemas.token import Token, RefreshTokenRequest, MFARequiredResponse
from app.schemas.user import User as UserSchema
from app.models.user import User as UserModel
# Importar Schemas MFA
from app.schemas.user import (
    ForgotPasswordRequest, ResetPasswordRequest,
    MFAEnableResponse, MFAConfirmRequest, MFADisableRequest, MFAVerifyRequest
)
from app.services.email_service import send_password_reset_email
from fastapi import Path, BackgroundTasks
from app.api.dependencies import get_current_active_user, oauth2_scheme
from app.core.exceptions import AccountLockedException
from jose import jwt, JWTError # Importar jwt e JWTError para challenge token

router = APIRouter()

# --- Constantes para o MFA Challenge Token ---
MFA_CHALLENGE_SECRET_KEY = settings.SECRET_KEY + "-mfa-challenge" # Usa a chave principal + sufixo
MFA_CHALLENGE_ALGORITHM = settings.ALGORITHM
MFA_CHALLENGE_EXPIRE_MINUTES = 5 # Token de desafio de curta duração

# --- Funções Helper para MFA Challenge Token ---
def create_mfa_challenge_token(user_id: int) -> str:
    """Cria um token JWT de curta duração para o desafio MFA."""
    expire = datetime.now(timezone.utc) + timedelta(minutes=MFA_CHALLENGE_EXPIRE_MINUTES)
    to_encode = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": expire,
        "sub": str(user_id),
        "token_type": "mfa_challenge" # Tipo específico
    }
    encoded_jwt = jwt.encode(to_encode, MFA_CHALLENGE_SECRET_KEY, algorithm=MFA_CHALLENGE_ALGORITHM)
    return encoded_jwt

def decode_mfa_challenge_token(token: str) -> Dict | None:
    """Decodifica e valida o token de desafio MFA."""
    try:
        payload = jwt.decode(
            token,
            MFA_CHALLENGE_SECRET_KEY,
            algorithms=[MFA_CHALLENGE_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            # --- CORREÇÃO AQUI ---
            issuer=settings.JWT_ISSUER, # Especifica o emissor esperado
            # --- FIM CORREÇÃO ---
            options={"verify_iss": True, "verify_aud": True}
        )
        # Verifica o tipo específico do token
        if payload.get("token_type") != "mfa_challenge":
            logger.warning("Tentativa de usar token com tipo incorreto como challenge token MFA.")
            return None
        return payload
    except JWTError as e:
        logger.warning(f"Erro ao decodificar challenge token MFA: {e}")
        return None
# --- Fim Funções Helper ---

# --- Endpoint /token Modificado ---
@router.post(
    "/token",
    response_model=Union[Token, MFARequiredResponse], # Resposta pode ser Token ou Desafio MFA
    responses={ # Documenta as possíveis respostas no Swagger
        200: {"description": "Login bem-sucedido ou MFA necessário", "model": Union[Token, MFARequiredResponse]},
        400: {"description": "Credenciais inválidas, conta bloqueada ou inativa"}
    }
)
async def login_for_access_token(
    db: AsyncSession = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
    response: Response = Response() # Para poder definir o status_code
) -> Any:
    """
    Login para obter Access e Refresh tokens.

    Se MFA estiver habilitado, retorna uma resposta indicando que a verificação MFA é necessária,
    junto com um 'mfa_challenge_token' para a próxima etapa (`/mfa/verify`).

    Opcionalmente, pode receber 'scope' no form-data (ex: "roles permissions")
    para injetar claims no Access Token (apenas se MFA não for necessário ou após verificação).
    """
    try:
        # Lógica de autenticação (EXISTENTE - verifica senha, lockout, status ativo/verificado)
        user = await crud_user.authenticate(db, email=form_data.username, password=form_data.password)
    except AccountLockedException as e:
        # Captura a exceção de conta bloqueada (EXISTENTE)
        detail_msg = "Account locked due to too many failed login attempts."
        if e.locked_until:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            if e.locked_until > now:
                remaining_minutes = int((e.locked_until - now).total_seconds() // 60) + 1
                detail_msg = f"Account locked. Try again in {remaining_minutes} minute(s)."
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail_msg)

    # Verificação de usuário válido (EXISTENTE)
    if not user:
        # O authenticate já tratou senha incorreta e lockout, então aqui só pode ser
        # usuário inativo/não verificado, ou não encontrado (embora authenticate devesse retornar None neste caso)
        user_check = await crud_user.get_by_email(db, email=form_data.username)
        if user_check and (not user_check.is_active or not user_check.is_verified):
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Conta inativa ou e-mail não verificado. Verifique seu e-mail.")
        # Se chegou aqui e user é None, a senha estava errada (tratado no authenticate)
        # ou o usuário não existe. Por segurança, retornamos a mesma mensagem genérica.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")

    # --- VERIFICAÇÃO MFA ---
    if user.is_mfa_enabled:
        # Se MFA está ativo, NÃO retorna os tokens ainda.
        # Gera um token de desafio de curta duração.
        mfa_challenge_token = create_mfa_challenge_token(user_id=user.id)

        # Define o status code da resposta como 200 OK (requer ação adicional do cliente)
        response.status_code = status.HTTP_200_OK
        # Retorna a resposta indicando que MFA é necessário
        logger.info(f"Login para {user.email}: MFA necessário, challenge token emitido.")
        return MFARequiredResponse(mfa_challenge_token=mfa_challenge_token)
    # --- FIM VERIFICAÇÃO MFA ---

    # --- Se MFA NÃO está ativo, continua o fluxo normal ---
    logger.info(f"Login para {user.email}: MFA não habilitado, emitindo tokens.")
    requested_scopes = form_data.scopes

    access_token = security.create_access_token(
        user=user,
        requested_scopes=requested_scopes,
        mfa_passed=False # MFA não foi necessário/passado nesta etapa
    )
    refresh_token_str, expires_at = security.create_refresh_token(
        data={"sub": str(user.id)}
    )
    await crud_refresh_token.create_refresh_token(
        db, user=user, token=refresh_token_str, expires_at=expires_at
    )

    # Define o status code como 200 OK
    response.status_code = status.HTTP_200_OK
    # Retorna os tokens normais
    return Token(
        access_token=access_token,
        refresh_token=refresh_token_str,
        token_type="bearer"
    )

# --- NOVOS ENDPOINTS MFA ---

@router.post("/mfa/enable", response_model=MFAEnableResponse)
async def enable_mfa_start(
    current_user: UserModel = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Inicia o processo de habilitação do MFA (requer autenticação via token JWT).
    Gera um segredo OTP, salva-o temporariamente no usuário (campo otp_secret),
    e retorna a URI e o QR Code para o usuário escanear no app autenticador.
    O MFA **não** está ativo ainda, requer confirmação via `/mfa/confirm`.
    """
    if current_user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA já está habilitado.")

    otp_secret = security.generate_otp_secret()

    # Salva o segredo temporariamente no usuário (mas NÃO ativa MFA ainda)
    try:
        # Usamos uma função CRUD para encapsular a lógica de salvar o segredo pendente
        await crud_user.set_pending_otp_secret(db=db, user=current_user, otp_secret=otp_secret)
    except ValueError as e: # Captura erro se MFA já estiver ativo (double check)
         raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Erro ao salvar segredo OTP pendente para {current_user.email}: {e}")
        raise HTTPException(status_code=500, detail="Erro ao iniciar habilitação do MFA.")


    otp_uri = security.generate_otp_uri(
        secret=otp_secret,
        email=current_user.email,
        # Tenta usar o nome configurado no .env, senão usa um default
        issuer_name=settings.EMAIL_FROM_NAME or "Verax Auth"
    )
    try:
        qr_code_base64 = security.generate_qr_code_base64(otp_uri)
    except Exception as e:
        logger.error(f"Erro ao gerar QR code para {current_user.email}: {e}")
        # Ainda retorna a URI, o frontend pode gerar o QR code se preferir
        qr_code_base64 = "" # Ou levanta um erro 500

    logger.info(f"Iniciada habilitação MFA para {current_user.email}. Segredo pendente salvo.")
    # Retorna APENAS a URI/QR Code para o usuário escanear
    # O segredo está guardado no backend esperando confirmação
    return MFAEnableResponse(
        otp_uri=otp_uri,
        qr_code_base64=qr_code_base64
    )

@router.post("/mfa/confirm", response_model=UserSchema)
async def enable_mfa_confirm(
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFAConfirmRequest,
    current_user: UserModel = Depends(get_current_active_user)
):
    """
    Confirma e habilita o MFA (requer autenticação via token JWT).
    O usuário deve ter chamado `/mfa/enable` antes e escaneado o QR Code.
    Verifica o código OTP inserido pelo usuário contra o segredo pendente salvo no banco.
    Se o código for válido, marca `is_mfa_enabled = True`.
    """
    if current_user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA já está habilitado.")

    # Tenta confirmar usando o segredo que está no DB (foi salvo pelo /enable)
    updated_user = await crud_user.confirm_mfa_enable(
        db=db,
        user=current_user,
        otp_code=mfa_data.otp_code
    )

    if not updated_user:
        # Se falhou, pode ser código inválido ou estado inconsistente (ex: secret não estava pendente)
        raise HTTPException(status_code=400, detail="Código OTP inválido ou falha ao confirmar MFA.")

    # Retorna o usuário atualizado (com is_mfa_enabled=True)
    return updated_user

@router.post("/mfa/disable", response_model=UserSchema)
async def disable_mfa(
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFADisableRequest,
    current_user: UserModel = Depends(get_current_active_user)
):
    """
    Desabilita o MFA para o usuário logado (requer autenticação via token JWT).
    Requer um código OTP válido do app autenticador para confirmar a desativação.
    """
    if not current_user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA não está habilitado.")

    # Tenta desabilitar verificando o código OTP atual
    updated_user = await crud_user.disable_mfa(
        db=db,
        user=current_user,
        otp_code=mfa_data.otp_code
    )

    if not updated_user:
        raise HTTPException(status_code=400, detail="Código OTP inválido.")

    # Retorna o usuário atualizado (com is_mfa_enabled=False e otp_secret=None)
    return updated_user

@router.post("/mfa/verify", response_model=Token)
async def verify_mfa_login(
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFAVerifyRequest
):
    """
    Verifica o código OTP durante o login (após a senha ser validada via `/token`).
    Recebe o 'mfa_challenge_token' (retornado pelo `/token`) e o 'otp_code' do usuário.
    Se válido, retorna os tokens de acesso e refresh finais.
    """
    # 1. Decodifica o token de desafio
    payload = decode_mfa_challenge_token(mfa_data.mfa_challenge_token)
    if not payload:
        raise HTTPException(status_code=400, detail="Token de desafio MFA inválido ou expirado.")

    user_id_str = payload.get("sub")
    if not user_id_str:
         raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sem sub).")

    try: user_id = int(user_id_str)
    except ValueError: raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sub inválido).")

    # 2. Busca o usuário
    user = await crud_user.get(db, id=user_id)
    # Verifica se usuário existe, está ativo, tem MFA habilitado e tem um segredo salvo
    if not user or not user.is_active or not user.is_mfa_enabled or not user.otp_secret:
        logger.warning(f"Tentativa de verificação MFA inválida para user ID {user_id}. Estado: user_exists={bool(user)}, active={getattr(user, 'is_active', None)}, mfa_enabled={getattr(user, 'is_mfa_enabled', None)}, secret_exists={bool(getattr(user, 'otp_secret', None))}")
        raise HTTPException(status_code=400, detail="Usuário inválido ou MFA não está (mais) habilitado.")

    # 3. Verifica o código OTP
    if not security.verify_otp_code(secret=user.otp_secret, code=mfa_data.otp_code):
        # Aqui NÃO incrementamos falha de login, pois a senha já foi validada.
        # Poderíamos implementar um bloqueio específico para falhas de MFA se desejado.
        logger.warning(f"Código OTP inválido na verificação MFA para {user.email}.")
        raise HTTPException(status_code=400, detail="Código OTP inválido.")

    # 4. Código OTP válido! Gera os tokens finais.
    logger.info(f"Verificação MFA bem-sucedida para {user.email}. Emitindo tokens finais.")
    # IMPORTANTE: Os scopes NÃO são passados aqui. Foram perdidos no desafio.
    # O cliente teria que solicitá-los novamente se precisasse deles imediatamente no frontend,
    # ou o backend cliente (VRSales) pode ignorar isso, pois ele valida o token e busca os dados necessários.
    # Vamos gerar o token indicando que o MFA foi passado (mfa_passed=True).
    access_token = security.create_access_token(user=user, mfa_passed=True)
    refresh_token_str, expires_at = security.create_refresh_token(data={"sub": str(user.id)})

    await crud_refresh_token.create_refresh_token(
        db, user=user, token=refresh_token_str, expires_at=expires_at
    )

    return Token(
        access_token=access_token,
        refresh_token=refresh_token_str,
        token_type="bearer"
    )

# --- FIM NOVOS ENDPOINTS MFA ---


# --- ENDPOINTS EXISTENTES (/refresh, /verify-email, etc.) ---
@router.post("/refresh", response_model=Token)
async def refresh_access_token(*, db: AsyncSession = Depends(get_db), refresh_request: RefreshTokenRequest) -> Any:
    refresh_token_str = refresh_request.refresh_token
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})
    payload = security.decode_refresh_token(refresh_token_str)
    if payload is None: raise credentials_exception
    user_id_str = payload.get("sub")
    if user_id_str is None: raise credentials_exception
    try: user_id = int(user_id_str)
    except ValueError: raise credentials_exception
    db_refresh_token = await crud_refresh_token.get_refresh_token(db, token=refresh_token_str)
    if not db_refresh_token or db_refresh_token.user_id != user_id: raise credentials_exception
    await crud_refresh_token.revoke_refresh_token(db, token=refresh_token_str)
    user = await crud_user.get(db, id=user_id)
    if not user or not user.is_active: raise credentials_exception
    # O Access Token gerado via refresh NUNCA tem o MFA como "passado", pois não houve verificação OTP.
    new_access_token = security.create_access_token(user=user, mfa_passed=False)
    new_refresh_token_str, new_expires_at = security.create_refresh_token(data={"sub": str(user.id)})
    await crud_refresh_token.create_refresh_token(db, user=user, token=new_refresh_token_str, expires_at=new_expires_at)
    return Token(access_token=new_access_token, refresh_token=new_refresh_token_str, token_type="bearer")


# ... ( /verify-email, /logout, /me, /forgot-password, /reset-password permanecem iguais) ...
@router.get("/verify-email/{token}", response_model=UserSchema)
async def verify_email(*, db: AsyncSession = Depends(get_db), token: str = Path(...)):
    user = await crud_user.verify_user_email(db, token=token)
    if not user: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token de verificação inválido ou expirado")
    logger.info(f"Email verificado com sucesso para usuário ID: {user.id}")
    return user

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(*, db: AsyncSession = Depends(get_db), refresh_request: RefreshTokenRequest):
    await crud_refresh_token.revoke_refresh_token(db, token=refresh_request.refresh_token)
    return None

@router.get("/me", response_model=UserSchema)
async def read_users_me(current_user: UserModel = Depends(get_current_active_user)) -> Any:
    return current_user

@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(*, db: AsyncSession = Depends(get_db), request_body: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    user = await crud_user.get_by_email(db, email=request_body.email)
    if user and user.is_active:
        try:
            db_user, reset_token = await crud_user.generate_password_reset_token(db, user=user)
            background_tasks.add_task(send_password_reset_email, email_to=db_user.email, reset_token=reset_token)
            logger.info(f"Solicitação de reset de senha para: {user.email}")
        except Exception as e:
            logger.error(f"Erro no fluxo /forgot-password para {request_body.email}: {e}")
    else:
        logger.warning(f"Tentativa de /forgot-password para email não existente ou inativo: {request_body.email}")
    return {"msg": "Se um usuário com esse email existir e estiver ativo, um link de redefinição será enviado."}

@router.post("/reset-password", response_model=UserSchema)
async def reset_password(*, db: AsyncSession = Depends(get_db), request_body: ResetPasswordRequest):
    token = request_body.token
    new_password = request_body.new_password
    payload = security.decode_password_reset_token(token)
    if not payload or not payload.get("sub"): raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token de redefinição inválido ou expirado (JWT)")
    email = payload["sub"]
    user = await crud_user.get_user_by_reset_token(db, token=token)
    if not user or user.email != email: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token de redefinição inválido, expirado ou já utilizado (DB)")
    try:
        updated_user = await crud_user.reset_password(db, user=user, new_password=new_password)
        logger.info(f"Senha redefinida com sucesso para o usuário: {user.email}")
        return updated_user
    except Exception as e:
        logger.error(f"Erro ao tentar redefinir a senha para {user.email}: {e}")
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Ocorreu um erro ao atualizar sua senha.")