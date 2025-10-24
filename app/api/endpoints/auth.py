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
from app.crud import crud_mfa_recovery_code
from app.db.session import get_db
from app.core import security
from app.core.config import settings
from app.schemas.token import (
    Token, RefreshTokenRequest, MFARequiredResponse,
    GoogleLoginUrlResponse, GoogleLoginRequest # <-- RE-ADICIONADO
)
from app.schemas.user import User as UserSchema
from app.models.user import User as UserModel
from app.schemas.user import (
    ForgotPasswordRequest, ResetPasswordRequest,
    MFAEnableResponse, 
    MFAConfirmRequest, MFADisableRequest, MFAVerifyRequest,
    MFAConfirmResponse, MFARecoveryRequest
)
from app.services.email_service import send_password_reset_email
from fastapi import Path, BackgroundTasks
from app.api.dependencies import get_current_active_user, oauth2_scheme
from app.core.exceptions import AccountLockedException
from jose import jwt, JWTError
import httpx


router = APIRouter()

# --- Constantes do Google OAuth ---
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
# ---------------------------------

# (Código existente das constantes e helpers do MFA - sem alterações)
# ... (O código MFA/JWT helpers permanece o mesmo) ...
MFA_CHALLENGE_SECRET_KEY = settings.SECRET_KEY + "-mfa-challenge" 
MFA_CHALLENGE_ALGORITHM = settings.ALGORITHM
MFA_CHALLENGE_EXPIRE_MINUTES = 5 

def create_mfa_challenge_token(user_id: int) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=MFA_CHALLENGE_EXPIRE_MINUTES)
    to_encode = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": expire,
        "sub": str(user_id),
        "token_type": "mfa_challenge"
    }
    encoded_jwt = jwt.encode(to_encode, MFA_CHALLENGE_SECRET_KEY, algorithm=MFA_CHALLENGE_ALGORITHM)
    return encoded_jwt

def decode_mfa_challenge_token(token: str) -> Dict | None:
    try:
        payload = jwt.decode(
            token,
            MFA_CHALLENGE_SECRET_KEY,
            algorithms=[MFA_CHALLENGE_ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER, 
            options={"verify_iss": True, "verify_aud": True}
        )
        if payload.get("token_type") != "mfa_challenge":
            logger.warning("Tentativa de usar token com tipo incorreto como challenge token MFA.")
            return None
        return payload
    except JWTError as e:
        logger.warning(f"Erro ao decodificar challenge token MFA: {e}")
        return None
# (Fim do código existente do MFA)


# --- Endpoint /token (EXISTENTE - sem alterações) ---
@router.post(
    "/token",
    response_model=Union[Token, MFARequiredResponse], 
    responses={ 
        200: {"description": "Login bem-sucedido ou MFA necessário", "model": Union[Token, MFARequiredResponse]},
        400: {"description": "Credenciais inválidas, conta bloqueada ou inativa"}
    }
)
async def login_for_access_token(
    db: AsyncSession = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
    response: Response = Response() 
) -> Any:
    # (Código existente - sem alterações)
    try:
        user = await crud_user.authenticate(db, email=form_data.username, password=form_data.password)
    except AccountLockedException as e:
        detail_msg = "Account locked due to too many failed login attempts."
        if e.locked_until:
            now = datetime.now(timezone.utc).replace(tzinfo=None)
            if e.locked_until > now:
                remaining_minutes = int((e.locked_until - now).total_seconds() // 60) + 1
                detail_msg = f"Account locked. Try again in {remaining_minutes} minute(s)."
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail_msg)

    if not user:
        user_check = await crud_user.get_by_email(db, email=form_data.username)
        if user_check and (not user_check.is_active or not user_check.is_verified):
             raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Conta inativa ou e-mail não verificado. Verifique seu e-mail.")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Incorrect email or password")

    if user.is_mfa_enabled:
        mfa_challenge_token = create_mfa_challenge_token(user_id=user.id)
        response.status_code = status.HTTP_200_OK
        logger.info(f"Login para {user.email}: MFA necessário, challenge token emitido.")
        return MFARequiredResponse(mfa_challenge_token=mfa_challenge_token)

    logger.info(f"Login para {user.email}: MFA não habilitado, emitindo tokens.")
    requested_scopes = form_data.scopes
    access_token = security.create_access_token(
        user=user,
        requested_scopes=requested_scopes,
        mfa_passed=False 
    )
    refresh_token_str, expires_at = security.create_refresh_token(
        data={"sub": str(user.id)}
    )
    await crud_refresh_token.create_refresh_token(
        db, user=user, token=refresh_token_str, expires_at=expires_at
    )
    response.status_code = status.HTTP_200_OK
    return Token(
        access_token=access_token,
        refresh_token=refresh_token_str,
        token_type="bearer"
    )

# --- ENDPOINTS GOOGLE OAUTH REVERTIDOS PARA PRODUÇÃO ---

@router.get("/google/login-url", response_model=GoogleLoginUrlResponse)
async def get_google_login_url():
    """
    Retorna o URL de autorização da Google para o frontend.
    O frontend deve redirecionar o utilizador para este URL.
    """
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_REDIRECT_URI_FRONTEND: # MODIFICADO
        logger.error("GOOGLE_CLIENT_ID ou GOOGLE_REDIRECT_URI_FRONTEND não estão configurados no .env")
        raise HTTPException(status_code=500, detail="Configuração OAuth está incompleta.")

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI_FRONTEND, # MODIFICADO
        "response_type": "code",
        "scope": "openid email profile", 
        "access_type": "offline",      
        "prompt": "select_account",    
    }
    
    request = httpx.Request("GET", GOOGLE_AUTH_URL, params=params)
    return GoogleLoginUrlResponse(url=str(request.url))

@router.post("/google/callback", response_model=Token) # MODIFICADO: De GET para POST
async def google_callback(
    *,
    db: AsyncSession = Depends(get_db),
    login_request: GoogleLoginRequest # MODIFICADO: Recebe JSON do frontend
):
    """
    Endpoint de callback para o login Google.
    O frontend recebe o 'code' da Google, envia para este endpoint.
    A API troca o 'code' por info do utilizador, cria/encontra o utilizador,
    e retorna os tokens JWT da *nossa* API.
    """
    code = login_request.code # MODIFICADO
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET or not settings.GOOGLE_REDIRECT_URI_FRONTEND: # MODIFICADO
        logger.error("Configurações OAuth da Google incompletas.")
        raise HTTPException(status_code=500, detail="Configuração OAuth está incompleta.")

    # --- 1. Trocar o 'code' por um token de acesso da Google ---
    token_data_payload = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI_FRONTEND, # MODIFICADO
        "grant_type": "authorization_code",
    }
    
    async with httpx.AsyncClient() as client:
        try:
            r = await client.post(GOOGLE_TOKEN_URL, data=token_data_payload)
            r.raise_for_status() 
            token_data = r.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Erro ao trocar código da Google: {e.response.json()}")
            raise HTTPException(status_code=400, detail="Código de autorização inválido ou expirado.")
        except Exception as e:
            logger.error(f"Erro de rede ao contactar Google Token URL: {e}")
            raise HTTPException(status_code=500, detail="Erro ao contactar serviço de login.")
            
    google_access_token = token_data.get("access_token")
    if not google_access_token:
        logger.error(f"Resposta da Google não continha 'access_token': {token_data}")
        raise HTTPException(status_code=500, detail="Falha ao obter token da Google.")

    # --- 2. Obter informações do utilizador da Google ---
    headers = {"Authorization": f"Bearer {google_access_token}"}
    async with httpx.AsyncClient() as client:
        try:
            r = await client.get(GOOGLE_USERINFO_URL, headers=headers)
            r.raise_for_status()
            user_info = r.json()
        except Exception as e:
            logger.error(f"Erro ao obter userinfo da Google: {e}")
            raise HTTPException(status_code=500, detail="Falha ao obter dados do utilizador.")

    email = user_info.get("email")
    full_name = user_info.get("name")
    
    if not email:
        raise HTTPException(status_code=400, detail="Email não retornado pela Google.")
    if not user_info.get("email_verified"):
        raise HTTPException(status_code=400, detail="Email da Google não está verificado.")

    # --- 3. Encontrar ou Criar o utilizador na nossa BD ---
    try:
        user = await crud_user.get_or_create_by_email_oauth(
            db=db, email=email, full_name=full_name
        )
    except Exception as e:
        logger.error(f"Erro ao criar/obter utilizador OAuth na BD: {e}")
        raise HTTPException(status_code=500, detail="Erro interno ao processar conta.")

    if not user.is_active:
         raise HTTPException(status_code=400, detail="Conta desativada.")

    # --- 4. Emitir os NOSSOS tokens JWT ---
    logger.info(f"Login OAuth bem-sucedido para {user.email}. Emitindo tokens.")
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

# --- FIM ENDPOINTS GOOGLE OAUTH ---


# --- Endpoints MFA (EXISTENTES - sem alterações) ---
# (O resto do ficheiro auth.py permanece o mesmo)
@router.post("/mfa/enable", response_model=MFAEnableResponse)
async def enable_mfa_start(
    current_user: UserModel = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    # (Código existente - sem alterações)
    if current_user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA já está habilitado.")
    otp_secret = security.generate_otp_secret()
    try:
        await crud_user.set_pending_otp_secret(db=db, user=current_user, otp_secret=otp_secret)
    except ValueError as e: 
         raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Erro ao salvar segredo OTP pendente para {current_user.email}: {e}")
        raise HTTPException(status_code=500, detail="Erro ao iniciar habilitação do MFA.")
    otp_uri = security.generate_otp_uri(
        secret=otp_secret,
        email=current_user.email,
        issuer_name=settings.EMAIL_FROM_NAME or "Verax"
    )
    try:
        qr_code_base64 = security.generate_qr_code_base64(otp_uri)
    except Exception as e:
        logger.error(f"Erro ao gerar QR code para {current_user.email}: {e}")
        qr_code_base64 = "" 
    logger.info(f"Iniciada habilitação MFA para {current_user.email}. Segredo pendente salvo.")
    return MFAEnableResponse(
        otp_uri=otp_uri,
        qr_code_base64=qr_code_base64
    )

@router.post("/mfa/confirm", response_model=MFAConfirmResponse) 
async def enable_mfa_confirm(
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFAConfirmRequest,
    current_user: UserModel = Depends(get_current_active_user)
):
    # (Código existente - sem alterações)
    if current_user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA já está habilitado.")

    result = await crud_user.confirm_mfa_enable(
        db=db,
        user=current_user,
        otp_code=mfa_data.otp_code
    )

    if not result:
        raise HTTPException(status_code=400, detail="Código OTP inválido ou falha ao confirmar MFA.")

    updated_user, plain_recovery_codes = result

    return MFAConfirmResponse(
        user=updated_user,
        recovery_codes=plain_recovery_codes
    )


@router.post("/mfa/disable", response_model=UserSchema)
async def disable_mfa(
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFADisableRequest,
    current_user: UserModel = Depends(get_current_active_user)
):
    # (Código existente - sem alterações)
    if not current_user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA não está habilitado.")

    updated_user = await crud_user.disable_mfa(
        db=db,
        user=current_user,
        otp_code=mfa_data.otp_code
    )

    if not updated_user:
        raise HTTPException(status_code=400, detail="Código OTP inválido.")
    return updated_user

@router.post("/mfa/verify", response_model=Token)
async def verify_mfa_login(
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFAVerifyRequest
):
    # (Código existente - sem alterações)
    payload = decode_mfa_challenge_token(mfa_data.mfa_challenge_token)
    if not payload:
        raise HTTPException(status_code=400, detail="Token de desafio MFA inválido ou expirado.")

    user_id_str = payload.get("sub")
    if not user_id_str:
         raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sem sub).")
    try: user_id = int(user_id_str)
    except ValueError: raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sub inválido).")

    user = await crud_user.get(db, id=user_id)
    if not user or not user.is_active or not user.is_mfa_enabled or not user.otp_secret:
        logger.warning(f"Tentativa de verificação MFA inválida para user ID {user_id}.")
        raise HTTPException(status_code=400, detail="Usuário inválido ou MFA não está (mais) habilitado.")

    if not security.verify_otp_code(secret=user.otp_secret, code=mfa_data.otp_code):
        logger.warning(f"Código OTP inválido na verificação MFA para {user.email}.")
        raise HTTPException(status_code=400, detail="Código OTP inválido.")

    logger.info(f"Verificação MFA (OTP) bem-sucedida para {user.email}. Emitindo tokens.")
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

@router.post("/mfa/verify-recovery", response_model=Token)
async def verify_mfa_recovery_login(
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFARecoveryRequest
):
    # (Código existente - sem alterações)
    payload = decode_mfa_challenge_token(mfa_data.mfa_challenge_token)
    if not payload:
        raise HTTPException(status_code=400, detail="Token de desafio MFA inválido ou expirado.")

    user_id_str = payload.get("sub")
    if not user_id_str:
         raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sem sub).")
    try: user_id = int(user_id_str)
    except ValueError: raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sub inválido).")

    user = await crud_user.get(db, id=user_id)
    if not user or not user.is_active or not user.is_mfa_enabled:
        logger.warning(f"Tentativa de recuperação MFA inválida para user ID {user_id}.")
        raise HTTPException(status_code=400, detail="Usuário inválido ou MFA não está habilitado.")

    db_code = await crud_mfa_recovery_code.get_valid_recovery_code(
        db=db, 
        user=user, 
plain_code=mfa_data.recovery_code
    )
    
    if not db_code:
        logger.warning(f"Código de recuperação inválido ou já utilizado para {user.email}.")
        raise HTTPException(status_code=400, detail="Código de recuperação inválido ou já utilizado.")

    await crud_mfa_recovery_code.mark_code_as_used(db=db, db_code=db_code)
    
    logger.info(f"Verificação MFA (RECOVERY CODE) bem-sucedida para {user.email}. Emitindo tokens.")
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
# (O resto do ficheiro permanece o mesmo)
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
    new_access_token = security.create_access_token(user=user, mfa_passed=False)
    new_refresh_token_str, new_expires_at = security.create_refresh_token(data={"sub": str(user.id)})
    await crud_refresh_token.create_refresh_token(db, user=user, token=new_refresh_token_str, expires_at=new_expires_at)
    return Token(access_token=new_access_token, refresh_token=new_refresh_token_str, token_type="bearer")

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