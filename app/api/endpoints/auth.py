# auth_api/app/api/endpoints/auth.py
from loguru import logger
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Union, List, Optional
from app.crud import crud_refresh_token, crud_mfa_recovery_code, crud_user
from fastapi import APIRouter, Depends, HTTPException, status, Response, Request, Path, BackgroundTasks # Adicionado Request, Response, Path, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

# Imports de dependências, schemas, modelos e core
from app.api.dependencies import get_current_active_user, get_db, oauth2_scheme # Adicionado oauth2_scheme (embora não usado diretamente nas rotas novas)
from app.db.session import get_db
from app.core import security
from app.core.config import settings
from app.core.exceptions import AccountLockedException

from app.schemas.token import (
    Token, RefreshTokenRequest, MFARequiredResponse,
    GoogleLoginUrlResponse, GoogleLoginRequest,
    SessionInfo # Schema para listar sessões
)
from app.schemas.user import User as UserSchema
from app.schemas.user import (
    ForgotPasswordRequest, ResetPasswordRequest,
    MFAEnableResponse,
    MFAConfirmRequest, MFADisableRequest, MFAVerifyRequest,
    MFAConfirmResponse, MFARecoveryRequest
)
from app.schemas.trusted_device import TrustedDeviceInfo # Schema para listar dispositivos confiáveis

from app.models.user import User as UserModel
# Importar CRUDs necessários
from app.crud import crud_trusted_device # CRUD para dispositivos confiáveis

from app.services.email_service import send_password_reset_email, send_verification_email # Serviços de email

# Outros imports
from jose import jwt, JWTError
import httpx


router = APIRouter()

# --- Constantes do Google OAuth ---
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
# ---------------------------------

# --- Constantes e Helpers MFA ---
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
# --- Fim Helpers MFA ---

# --- Função Helper para Detalhes da Sessão/Requisição ---
def get_session_details(request: Request) -> Dict[str, Optional[str]]:
    """Extrai IP e User-Agent do request."""
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent")
    return {"ip_address": ip_address, "user_agent": user_agent}
# --- Fim Helper ---


# --- Endpoint /token (Login Principal) ---
@router.post(
    "/token",
    response_model=Union[Token, MFARequiredResponse],
    responses={
        200: {"description": "Login bem-sucedido ou MFA necessário", "model": Union[Token, MFARequiredResponse]},
        400: {"description": "Credenciais inválidas, conta bloqueada ou inativa"}
    }
)
async def login_for_access_token(
    request: Request,
    response: Response, # Injetar Response para poder setar cookies
    db: AsyncSession = Depends(get_db),
    form_data: OAuth2PasswordRequestForm = Depends(),
) -> Any:
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

    # --- Lógica de Device Trust ---
    is_device_trusted = False
    device_cookie = request.cookies.get(settings.TRUSTED_DEVICE_COOKIE_NAME)
    if device_cookie:
        trusted_device = await crud_trusted_device.get_trusted_device_by_token(db, plain_token=device_cookie)
        # Verifica se o token do cookie é válido E pertence ao usuário que está tentando logar
        if trusted_device and trusted_device.user_id == user.id:
            is_device_trusted = True
            logger.info(f"Login para {user.email}: Dispositivo confiável detectado (ID: {trusted_device.id}).")
    # --- Fim Lógica Device Trust ---

    # Se MFA está habilitado E o dispositivo NÃO é confiável
    if user.is_mfa_enabled and not is_device_trusted:
        mfa_challenge_token = create_mfa_challenge_token(user_id=user.id)
        logger.info(f"Login para {user.email}: MFA necessário (dispositivo não confiável), challenge token emitido.")
        # Retorna 200 OK com o challenge (não é um erro)
        return MFARequiredResponse(mfa_challenge_token=mfa_challenge_token)

    # --- Login bem-sucedido (MFA não habilitado, ou dispositivo confiável) ---
    logger.info(f"Login para {user.email}: Sucesso. Emitindo tokens.")
    requested_scopes = form_data.scopes
    # Se MFA está habilitado, significa que foi pulado pelo device trust, então mfa_passed=True
    access_token = security.create_access_token(
        user=user,
        requested_scopes=requested_scopes,
        mfa_passed=user.is_mfa_enabled # Se MFA está habilitado, foi 'passado' aqui
    )
    refresh_token_str, expires_at = security.create_refresh_token(
        data={"sub": str(user.id)}
    )

    session_details = get_session_details(request)
    await crud_refresh_token.create_refresh_token(
        db,
        user=user,
        token=refresh_token_str,
        expires_at=expires_at,
        ip_address=session_details.get("ip_address"),
        user_agent=session_details.get("user_agent")
    )

    # Se MFA foi pulado por causa do dispositivo confiável, NÃO precisamos setar novo cookie.
    # Se MFA NUNCA foi habilitado, também não setamos o cookie (ainda).
    # O cookie só será setado APÓS o /mfa/verify ou /mfa/verify-recovery.

    # O status 200 OK é o padrão para FastAPI se não houver erro
    return Token(
        access_token=access_token,
        refresh_token=refresh_token_str,
        token_type="bearer"
    )

# --- Endpoints Google OAuth ---
@router.get("/google/login-url", response_model=GoogleLoginUrlResponse)
async def get_google_login_url():
    """Retorna o URL de autorização da Google para o frontend."""
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_REDIRECT_URI_FRONTEND:
        logger.error("GOOGLE_CLIENT_ID ou GOOGLE_REDIRECT_URI_FRONTEND não estão configurados no .env")
        raise HTTPException(status_code=500, detail="Configuração OAuth está incompleta.")

    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI_FRONTEND,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "select_account",
    }

    request_obj = httpx.Request("GET", GOOGLE_AUTH_URL, params=params)
    return GoogleLoginUrlResponse(url=str(request_obj.url))

@router.post("/google/callback", response_model=Token)
async def google_callback(
    request: Request,
    response: Response, # Para setar o cookie de device trust
    *,
    db: AsyncSession = Depends(get_db),
    login_request: GoogleLoginRequest
):
    """Endpoint de callback para o login Google."""
    code = login_request.code
    if not settings.GOOGLE_CLIENT_ID or not settings.GOOGLE_CLIENT_SECRET or not settings.GOOGLE_REDIRECT_URI_FRONTEND:
        logger.error("Configurações OAuth da Google incompletas.")
        raise HTTPException(status_code=500, detail="Configuração OAuth está incompleta.")

    # 1. Trocar o 'code' por um token de acesso da Google
    token_data_payload = {
        "code": code,
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI_FRONTEND,
        "grant_type": "authorization_code",
    }
    async with httpx.AsyncClient() as client:
        # ... (try/except para a chamada httpx.post) ...
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
         raise HTTPException(status_code=500, detail="Falha ao obter token da Google.")

    # 2. Obter informações do utilizador da Google
    headers = {"Authorization": f"Bearer {google_access_token}"}
    async with httpx.AsyncClient() as client:
        # ... (try/except para a chamada httpx.get userinfo) ...
        try:
            r = await client.get(GOOGLE_USERINFO_URL, headers=headers)
            r.raise_for_status()
            user_info = r.json()
        except Exception as e:
            logger.error(f"Erro ao obter userinfo da Google: {e}")
            raise HTTPException(status_code=500, detail="Falha ao obter dados do utilizador.")

    email = user_info.get("email")
    full_name = user_info.get("name")
    if not email: raise HTTPException(status_code=400, detail="Email não retornado pela Google.")
    if not user_info.get("email_verified"): raise HTTPException(status_code=400, detail="Email da Google não está verificado.")

    # 3. Encontrar ou Criar o utilizador na nossa BD
    try:
        user = await crud_user.get_or_create_by_email_oauth(db=db, email=email, full_name=full_name)
    except Exception as e:
        logger.error(f"Erro ao criar/obter utilizador OAuth na BD: {e}")
        raise HTTPException(status_code=500, detail="Erro interno ao processar conta.")

    if not user.is_active: raise HTTPException(status_code=400, detail="Conta desativada.")

    # 4. Emitir os NOSSOS tokens JWT
    logger.info(f"Login OAuth bem-sucedido para {user.email}. Emitindo tokens.")
    # Login social é considerado seguro (como passar MFA)
    access_token = security.create_access_token(user=user, mfa_passed=True)
    refresh_token_str, expires_at = security.create_refresh_token(data={"sub": str(user.id)})

    session_details = get_session_details(request)
    await crud_refresh_token.create_refresh_token(
        db,
        user=user,
        token=refresh_token_str,
        expires_at=expires_at,
        ip_address=session_details.get("ip_address"),
        user_agent=session_details.get("user_agent")
    )

    # --- CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE (após login OAuth) ---
    _, plain_device_token = await crud_trusted_device.create_trusted_device(
        db, user=user,
        ip_address=session_details.get("ip_address"),
        user_agent=session_details.get("user_agent")
    )
    response.set_cookie(
        key=settings.TRUSTED_DEVICE_COOKIE_NAME,
        value=plain_device_token,
        max_age=timedelta(days=settings.TRUSTED_DEVICE_COOKIE_MAX_AGE_DAYS).total_seconds(),
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https", # True em produção
        path="/"
    )
    logger.info(f"Cookie de dispositivo confiável definido para {user.email} após login OAuth.")
    # --- FIM DEVICE TRUST ---

    return Token(
        access_token=access_token,
        refresh_token=refresh_token_str,
        token_type="bearer"
    )

# --- Endpoints MFA ---
@router.post("/mfa/enable", response_model=MFAEnableResponse)
async def enable_mfa_start(
    current_user: UserModel = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    # (Sem alterações)
    if current_user.is_mfa_enabled: raise HTTPException(status_code=400, detail="MFA já está habilitado.")
    otp_secret = security.generate_otp_secret()
    try:
        await crud_user.set_pending_otp_secret(db=db, user=current_user, otp_secret=otp_secret)
    except ValueError as e: raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Erro ao salvar segredo OTP pendente para {current_user.email}: {e}")
        raise HTTPException(status_code=500, detail="Erro ao iniciar habilitação do MFA.")
    otp_uri = security.generate_otp_uri(secret=otp_secret, email=current_user.email, issuer_name=settings.EMAIL_FROM_NAME or "Verax Auth")
    try: qr_code_base64 = security.generate_qr_code_base64(otp_uri)
    except Exception as e:
        logger.error(f"Erro ao gerar QR code para {current_user.email}: {e}")
        qr_code_base64 = ""
    logger.info(f"Iniciada habilitação MFA para {current_user.email}. Segredo pendente salvo.")
    return MFAEnableResponse(otp_uri=otp_uri, qr_code_base64=qr_code_base64)

@router.post("/mfa/confirm", response_model=MFAConfirmResponse)
async def enable_mfa_confirm(
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFAConfirmRequest,
    current_user: UserModel = Depends(get_current_active_user)
):
    # (Sem alterações)
    if current_user.is_mfa_enabled: raise HTTPException(status_code=400, detail="MFA já está habilitado.")
    result = await crud_user.confirm_mfa_enable(db=db, user=current_user, otp_code=mfa_data.otp_code)
    if not result: raise HTTPException(status_code=400, detail="Código OTP inválido ou falha ao confirmar MFA.")
    updated_user, plain_recovery_codes = result
    return MFAConfirmResponse(user=updated_user, recovery_codes=plain_recovery_codes)

@router.post("/mfa/disable", response_model=UserSchema)
async def disable_mfa(
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFADisableRequest,
    current_user: UserModel = Depends(get_current_active_user)
):
    # (Sem alterações)
    if not current_user.is_mfa_enabled: raise HTTPException(status_code=400, detail="MFA não está habilitado.")
    updated_user = await crud_user.disable_mfa(db=db, user=current_user, otp_code=mfa_data.otp_code)
    if not updated_user: raise HTTPException(status_code=400, detail="Código OTP inválido.")
    return updated_user

@router.post("/mfa/verify", response_model=Token)
async def verify_mfa_login(
    request: Request,
    response: Response, # Para setar o cookie
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFAVerifyRequest
):
    payload = decode_mfa_challenge_token(mfa_data.mfa_challenge_token)
    if not payload: raise HTTPException(status_code=400, detail="Token de desafio MFA inválido ou expirado.")
    user_id_str = payload.get("sub")
    if not user_id_str: raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sem sub).")
    try: user_id = int(user_id_str)
    except ValueError: raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sub inválido).")

    user = await crud_user.get(db, id=user_id)
    if not user or not user.is_active or not user.is_mfa_enabled or not user.otp_secret:
        raise HTTPException(status_code=400, detail="Usuário inválido ou MFA não está (mais) habilitado.")

    if not security.verify_otp_code(secret=user.otp_secret, code=mfa_data.otp_code):
        raise HTTPException(status_code=400, detail="Código OTP inválido.")

    # --- Login MFA (OTP) bem-sucedido ---
    logger.info(f"Verificação MFA (OTP) bem-sucedida para {user.email}. Emitindo tokens.")
    access_token = security.create_access_token(user=user, mfa_passed=True)
    refresh_token_str, expires_at = security.create_refresh_token(data={"sub": str(user.id)})
    session_details = get_session_details(request)
    await crud_refresh_token.create_refresh_token(
        db, user=user, token=refresh_token_str, expires_at=expires_at,
        ip_address=session_details.get("ip_address"), user_agent=session_details.get("user_agent")
    )

    # --- CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE ---
    _, plain_device_token = await crud_trusted_device.create_trusted_device(
        db, user=user,
        ip_address=session_details.get("ip_address"),
        user_agent=session_details.get("user_agent")
    )
    response.set_cookie(
        key=settings.TRUSTED_DEVICE_COOKIE_NAME,
        value=plain_device_token,
        max_age=timedelta(days=settings.TRUSTED_DEVICE_COOKIE_MAX_AGE_DAYS).total_seconds(),
        httponly=True,       # Essencial para segurança
        samesite="lax",      # Bom padrão
        secure=request.url.scheme == "https", # True em produção com HTTPS
        path="/"             # Cookie disponível em todo o domínio
    )
    logger.info(f"Cookie de dispositivo confiável definido para {user.email}.")
    # --- FIM DEVICE TRUST ---

    return Token(access_token=access_token, refresh_token=refresh_token_str, token_type="bearer")

@router.post("/mfa/verify-recovery", response_model=Token)
async def verify_mfa_recovery_login(
    request: Request,
    response: Response, # Para setar o cookie
    *,
    db: AsyncSession = Depends(get_db),
    mfa_data: MFARecoveryRequest
):
    payload = decode_mfa_challenge_token(mfa_data.mfa_challenge_token)
    if not payload: raise HTTPException(status_code=400, detail="Token de desafio MFA inválido ou expirado.")
    user_id_str = payload.get("sub")
    if not user_id_str: raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sem sub).")
    try: user_id = int(user_id_str)
    except ValueError: raise HTTPException(status_code=400, detail="Token de desafio MFA inválido (sub inválido).")

    user = await crud_user.get(db, id=user_id)
    if not user or not user.is_active or not user.is_mfa_enabled:
        raise HTTPException(status_code=400, detail="Usuário inválido ou MFA não está habilitado.")

    db_code = await crud_mfa_recovery_code.get_valid_recovery_code(db=db, user=user, plain_code=mfa_data.recovery_code)
    if not db_code: raise HTTPException(status_code=400, detail="Código de recuperação inválido ou já utilizado.")

    # --- Login MFA (Recovery) bem-sucedido ---
    await crud_mfa_recovery_code.mark_code_as_used(db=db, db_code=db_code)
    logger.info(f"Verificação MFA (RECOVERY CODE) bem-sucedida para {user.email}. Emitindo tokens.")
    access_token = security.create_access_token(user=user, mfa_passed=True)
    refresh_token_str, expires_at = security.create_refresh_token(data={"sub": str(user.id)})
    session_details = get_session_details(request)
    await crud_refresh_token.create_refresh_token(
        db, user=user, token=refresh_token_str, expires_at=expires_at,
        ip_address=session_details.get("ip_address"), user_agent=session_details.get("user_agent")
    )

    # --- CRIAR DISPOSITIVO CONFIÁVEL E SETAR COOKIE ---
    _, plain_device_token = await crud_trusted_device.create_trusted_device(
        db, user=user,
        ip_address=session_details.get("ip_address"),
        user_agent=session_details.get("user_agent")
    )
    response.set_cookie(
        key=settings.TRUSTED_DEVICE_COOKIE_NAME,
        value=plain_device_token,
        max_age=timedelta(days=settings.TRUSTED_DEVICE_COOKIE_MAX_AGE_DAYS).total_seconds(),
        httponly=True,
        samesite="lax",
        secure=request.url.scheme == "https", # True em produção
        path="/"
    )
    logger.info(f"Cookie de dispositivo confiável definido para {user.email}.")
    # --- FIM DEVICE TRUST ---

    return Token(access_token=access_token, refresh_token=refresh_token_str, token_type="bearer")

# --- Outros Endpoints de Autenticação ---
@router.post("/refresh", response_model=Token)
async def refresh_access_token(
    request: Request, # Para obter IP/UA
    *,
    db: AsyncSession = Depends(get_db),
    refresh_request: RefreshTokenRequest
) -> Any:
    refresh_token_str = refresh_request.refresh_token
    credentials_exception = HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials", headers={"WWW-Authenticate": "Bearer"})

    payload = security.decode_refresh_token(refresh_token_str)
    if payload is None: raise credentials_exception
    user_id_str = payload.get("sub")
    if user_id_str is None: raise credentials_exception
    try: user_id = int(user_id_str)
    except ValueError: raise credentials_exception

    db_refresh_token = await crud_refresh_token.get_refresh_token(db, token=refresh_token_str)
    if not db_refresh_token or db_refresh_token.user_id != user_id:
        raise credentials_exception

    # Revogar o token antigo
    await crud_refresh_token.revoke_refresh_token(db, token=refresh_token_str)

    user = await crud_user.get(db, id=user_id)
    if not user or not user.is_active: raise credentials_exception

    # Criar novos tokens
    # Ao refrescar, não garantimos que MFA foi passado recentemente, por isso mfa_passed=False
    new_access_token = security.create_access_token(user=user, mfa_passed=False)
    new_refresh_token_str, new_expires_at = security.create_refresh_token(data={"sub": str(user.id)})

    # Criar o novo registro de refresh token com IP/UA atuais
    session_details = get_session_details(request)
    await crud_refresh_token.create_refresh_token(
        db,
        user=user,
        token=new_refresh_token_str,
        expires_at=new_expires_at,
        ip_address=session_details.get("ip_address"),
        user_agent=session_details.get("user_agent")
    )

    return Token(access_token=new_access_token, refresh_token=new_refresh_token_str, token_type="bearer")

@router.get("/verify-email/{token}", response_model=UserSchema)
async def verify_email(*, db: AsyncSession = Depends(get_db), token: str = Path(...)):
    # (Sem alterações)
    user = await crud_user.verify_user_email(db, token=token)
    if not user: raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token de verificação inválido ou expirado")
    logger.info(f"Email verificado com sucesso para usuário ID: {user.id}")
    return user

@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    response: Response, # Para poder apagar o cookie de device trust
    request: Request,   # Para saber se o cookie deve ser secure
    *,
    db: AsyncSession = Depends(get_db),
    refresh_request: RefreshTokenRequest
):
    """Desloga a sessão atual revogando o refresh token e apagando o cookie de device trust."""
    revoked = await crud_refresh_token.revoke_refresh_token(db, token=refresh_request.refresh_token)
    if revoked:
         logger.info("Refresh token revogado com sucesso durante o logout.")

    # Apagar o cookie de dispositivo confiável ao fazer logout
    response.delete_cookie(
        key=settings.TRUSTED_DEVICE_COOKIE_NAME,
        path="/",
        secure=request.url.scheme == "https", # True em produção
        httponly=True,
        samesite="lax"
    )
    logger.info("Cookie de dispositivo confiável removido durante o logout.")

    # Retorna 204 No Content independentemente se o token foi encontrado/revogado
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserSchema)
async def read_users_me(current_user: UserModel = Depends(get_current_active_user)) -> Any:
    # (Sem alterações)
    return current_user

@router.post("/forgot-password", status_code=status.HTTP_202_ACCEPTED)
async def forgot_password(*, db: AsyncSession = Depends(get_db), request_body: ForgotPasswordRequest, background_tasks: BackgroundTasks):
    # (Sem alterações)
    user = await crud_user.get_by_email(db, email=request_body.email)
    if user and user.is_active:
        try:
            db_user, reset_token = await crud_user.generate_password_reset_token(db, user=user)
            background_tasks.add_task(send_password_reset_email, email_to=db_user.email, reset_token=reset_token)
            logger.info(f"Solicitação de reset de senha para: {user.email}")
        except Exception as e: logger.error(f"Erro no fluxo /forgot-password para {request_body.email}: {e}")
    else: logger.warning(f"Tentativa de /forgot-password para email não existente ou inativo: {request_body.email}")
    return {"msg": "Se um usuário com esse email existir e estiver ativo, um link de redefinição será enviado."}

@router.post("/reset-password", response_model=UserSchema)
async def reset_password(*, db: AsyncSession = Depends(get_db), request_body: ResetPasswordRequest):
    # (Sem alterações)
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

# --- Endpoints de Gestão de Sessão ---
@router.get("/sessions", response_model=List[SessionInfo])
async def get_active_sessions(
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_active_user)
):
    """Lista todas as sessões de login ativas (refresh tokens válidos) para o usuário autenticado."""
    sessions = await crud_refresh_token.get_active_sessions_for_user(
        db, user_id=current_user.id
    )
    return sessions

@router.delete("/sessions/all", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all_sessions(
    response: Response, # Para apagar o cookie atual
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_active_user)
):
    """Desconecta TODAS as sessões do usuário, revogando todos os refresh tokens."""
    revoked_count = await crud_refresh_token.revoke_all_refresh_tokens_for_user(
        db, user_id=current_user.id, exclude_token_hash=None # Revoga todos
    )
    logger.info(f"Usuário {current_user.email} revogou todas as {revoked_count} sessões.")

    # Apagar também o cookie de dispositivo confiável atual
    response.delete_cookie(
        key=settings.TRUSTED_DEVICE_COOKIE_NAME, path="/",
        secure=request.url.scheme == "https", httponly=True, samesite="lax"
    )
    logger.info("Cookie de dispositivo confiável removido durante logout de todas as sessões.")

    return Response(status_code=status.HTTP_204_NO_CONTENT)

@router.post("/sessions/all-except-current", status_code=status.HTTP_204_NO_CONTENT)
async def logout_all_except_current_session(
    refresh_request: RefreshTokenRequest, # Token atual no body
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_active_user)
):
    """Desconecta todas as sessões do usuário, EXCETO a sessão atual (identificada pelo refresh token enviado no corpo)."""
    try:
        token_hash_to_exclude = crud_refresh_token.hash_token(refresh_request.refresh_token)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid refresh token format")

    # Verifica se o token a excluir é válido e pertence ao usuário
    sessions = await crud_refresh_token.get_active_sessions_for_user(db, user_id=current_user.id)
    if not any(s.token_hash == token_hash_to_exclude for s in sessions):
        raise HTTPException(status_code=403, detail="Refresh token not found or invalid for this user")

    revoked_count = await crud_refresh_token.revoke_all_refresh_tokens_for_user(
        db, user_id=current_user.id, exclude_token_hash=token_hash_to_exclude
    )
    logger.info(f"Usuário {current_user.email} revogou {revoked_count} outras sessões.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.delete("/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
async def logout_specific_session(
    session_id: int,
    request: Request,   # Para ler o cookie atual
    response: Response, # Para apagar o cookie se necessário
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_active_user)
):
    """Desconecta uma sessão específica (revoga um refresh token) pelo seu ID numérico."""
    db_token = await crud_refresh_token.get_refresh_token_by_id(
        db, token_id=session_id, user_id=current_user.id
    )

    if not db_token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Sessão não encontrada ou não pertence a este usuário."
        )

    # Verifica se o cookie de dispositivo confiável atual corresponde ao hash do token desta sessão
    # (Embora não haja link direto, podemos revogar o cookie se estamos revogando a sessão associada
    #  à criação desse cookie, assumindo que foi criado junto)
    # Esta parte é opcional e menos precisa, pois não ligamos diretamente device_token a refresh_token
    # current_device_cookie = request.cookies.get(settings.TRUSTED_DEVICE_COOKIE_NAME)
    # if current_device_cookie:
    #     # Lógica para verificar se o cookie atual pode ter sido gerado por esta sessão e apagá-lo
    #     pass


    # Revoga o refresh token (sessão)
    await crud_refresh_token.revoke_refresh_token_by_id(db, db_token=db_token)
    logger.info(f"Usuário {current_user.email} revogou a sessão ID {session_id}.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- Endpoints de Gestão de Dispositivos Confiáveis ---
@router.get("/devices", response_model=List[TrustedDeviceInfo])
async def get_trusted_devices(
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_active_user)
):
    """Lista todos os dispositivos marcados como confiáveis para o usuário autenticado."""
    devices = await crud_trusted_device.get_trusted_devices_for_user(
        db, user_id=current_user.id
    )
    return devices

@router.delete("/devices/{device_id}", status_code=status.HTTP_204_NO_CONTENT)
async def forget_trusted_device(
    device_id: int,
    request: Request, # Para ler o cookie
    response: Response, # Para apagar o cookie
    db: AsyncSession = Depends(get_db),
    current_user: UserModel = Depends(get_current_active_user)
):
    """Remove um dispositivo específico da lista de dispositivos confiáveis."""
    db_device = await crud_trusted_device.get_trusted_device_by_id(
        db, device_id=device_id, user_id=current_user.id
    )

    if not db_device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dispositivo confiável não encontrado ou não pertence a este usuário."
        )

    # Verifica se o cookie atual corresponde ao dispositivo que está sendo removido
    current_device_cookie = request.cookies.get(settings.TRUSTED_DEVICE_COOKIE_NAME)
    if current_device_cookie:
        try:
            current_hash = crud_trusted_device.hash_device_token(current_device_cookie)
            if current_hash == db_device.device_token_hash:
                # Apaga o cookie do navegador se estamos removendo o dispositivo atu    
                response.delete_cookie(
                    key=settings.TRUSTED_DEVICE_COOKIE_NAME,
                    path="/",
                    secure=request.url.scheme == "https", # True em produção
                    httponly=True,
                    samesite="lax"
                )
                logger.info(f"Cookie do dispositivo confiável atual (ID: {device_id}    removido para {current_user.email}.")
        except Exception as e:
            logger.warning(f"Erro ao processar/remover cookie de dispositivo confiáv     durante a exclusão: {e}")


    await crud_trusted_device.delete_trusted_device(db, db_device=db_device)
    logger.info(f"Usuário {current_user.email} removeu o dispositivo confiável ID {device_id}.")
    # O status 204 é definido no decorador do endpoint
    # Não precisa retornar Response explicitamente aqui se não houver conteúdo