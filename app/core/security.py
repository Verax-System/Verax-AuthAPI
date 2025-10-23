# auth_api/app/core/security.py
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from passlib.context import CryptContext
from jose import jwt, JWTError
from .config import settings
import secrets
# Import UserModel QUALIFICADO para evitar conflito de nome 'User'
from app.models.user import User as UserModel
# --- NOVOS IMPORTS MFA ---
import pyotp
import qrcode # type: ignore
import io
import base64
# --- FIM NOVOS IMPORTS ---

# --- IMPORT DO LOGGER REMOVIDO ---
# from loguru import logger
# --- FIM IMPORT ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ... (verify_password, get_password_hash) ...
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        # Limita o tamanho da senha ANTES de passar para o bcrypt (evita erros > 72 bytes)
        password_bytes = plain_password.encode('utf-8')[:72]
        return pwd_context.verify(password_bytes, hashed_password)
    except Exception:
        # Consider logging the exception here for debugging potential issues
        return False

def get_password_hash(password: str) -> str:
    # Limita o tamanho da senha ANTES de passar para o bcrypt
    password_bytes = password.encode('utf-8')[:72]
    return pwd_context.hash(password_bytes)


# --- Funções JWT (com Claims OIDC) ---
def create_access_token(
    user: UserModel,
    requested_scopes: Optional[list[str]] = None,
    mfa_passed: bool = True # NOVO: Indica se o MFA foi verificado nesta sessão
) -> str:
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode: Dict[str, Any] = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "iat": now,
        "nbf": now,
        "exp": expire,
        "sub": str(user.id),
        "token_type": "access",
        "email": user.email,
        "email_verified": user.is_verified,
        # NOVO: Authentication Methods Reference (OIDC claim)
        # Se MFA está desabilitado OU se MFA está habilitado E foi passado nesta sessão -> ["pwd", "mfa"]
        # Caso contrário (MFA habilitado mas não passado) -> ["pwd"]
        "amr": ["pwd", "mfa"] if user.is_mfa_enabled and mfa_passed else ["pwd"],
        **({"name": user.full_name} if user.full_name else {})
    }
    if user.custom_claims and requested_scopes:
        for scope in requested_scopes:
            if scope in user.custom_claims and scope not in to_encode:
                to_encode[scope] = user.custom_claims.get(scope)
    encoded_jwt = jwt.encode(
        to_encode,
        settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt

# ... (decode_access_token, create_refresh_token, decode_refresh_token) ...
def decode_access_token(token: str) -> Dict | None:
    try:
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER, # Especifica o emissor esperado
            options={"verify_iss": True, "verify_aud": True}
        )
        return payload
    except JWTError as e:
        # --- LOG DE ERRO REMOVIDO ---
        # logger.error(f"Erro ao decodificar Access Token: {e}")
        # --- FIM LOG DE ERRO ---
        return None

def create_refresh_token(data: Dict[str, Any]) -> tuple[str, datetime]:
    to_encode = data.copy()
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({
        "iss": settings.JWT_ISSUER,
        "exp": expire,
        "token_type": "refresh"
    })
    encoded_jwt = jwt.encode(to_encode, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt, expire.replace(tzinfo=None)

def decode_refresh_token(token: str) -> Dict | None:
    try:
        payload = jwt.decode(
            token,
            settings.REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer=settings.JWT_ISSUER, # Especifica o emissor esperado
            options={"verify_iss": True, "verify_aud": False}
        )
        if payload.get("token_type") != "refresh":
             return None
        return payload
    except JWTError as e:
        # --- LOG DE ERRO REMOVIDO ---
        # logger.error(f"Erro ao decodificar Refresh Token: {e}")
        # --- FIM LOG DE ERRO ---
        return None

# ... (create_password_reset_token, decode_password_reset_token) ...
def create_password_reset_token(email: str) -> tuple[str, datetime]:
    reset_secret = settings.RESET_PASSWORD_SECRET_KEY or settings.SECRET_KEY
    expires_delta = timedelta(minutes=settings.RESET_PASSWORD_TOKEN_EXPIRE_MINUTES)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {
        "iss": settings.JWT_ISSUER,
        "aud": settings.JWT_AUDIENCE,
        "exp": expire,
        "nfs": datetime.now(timezone.utc),
        "sub": email,
        "token_type": "password_reset"
    }
    encoded_jwt = jwt.encode(to_encode, reset_secret, algorithm=settings.ALGORITHM)
    return encoded_jwt, expire.replace(tzinfo=None)

def decode_password_reset_token(token: str) -> Dict | None:
    try:
        reset_secret = settings.RESET_PASSWORD_SECRET_KEY or settings.SECRET_KEY
        payload = jwt.decode(
            token,
            reset_secret,
            algorithms=[settings.ALGORITHM],
            audience=settings.JWT_AUDIENCE,
            issuer=settings.JWT_ISSUER, # Especifica o emissor esperado
            options={"verify_iss": True, "verify_aud": True}
        )
        if payload.get("token_type") != "password_reset" or "sub" not in payload:
             return None
        return payload
    except JWTError as e:
        # --- LOG DE ERRO REMOVIDO ---
        # logger.error(f"Erro ao decodificar Password Reset Token: {e}")
        # --- FIM LOG DE ERRO ---
        return None

# --- NOVAS FUNÇÕES MFA/OTP ---

def generate_otp_secret() -> str:
    """Gera um novo segredo OTP seguro (base32)."""
    return pyotp.random_base32()

def generate_otp_uri(secret: str, email: str, issuer_name: str) -> str:
    """
    Gera uma URI 'otpauth://' que pode ser usada por apps autenticadores.
    """
    # Garante que o nome do issuer não tenha caracteres problemáticos para URI
    safe_issuer_name = issuer_name.replace(":", "")
    # Usa url_encode=True para garantir que o issuer_name seja codificado corretamente se contiver espaços, etc.
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name=safe_issuer_name
    )

def verify_otp_code(secret: str, code: str) -> bool:
    """
    Verifica se um código OTP é válido para o segredo fornecido.
    Permite uma pequena janela de tempo para sincronização.
    """
    if not secret: # Adiciona verificação se o segredo é nulo/Vazio
        return False
    totp = pyotp.TOTP(secret)
    # Verifica o código atual e o anterior/seguinte (janela de +/- 30s = 1 * 30s)
    return totp.verify(code, valid_window=1)

def generate_qr_code_base64(otp_uri: str) -> str:
    """Gera um QR Code a partir da URI OTP e retorna como imagem base64."""
    # Cria o QR code
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(otp_uri)
    qr.make(fit=True)

    # Cria a imagem a partir do QR code
    img = qr.make_image(fill_color="black", back_color="white")

    # Salva a imagem em memória como PNG
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")

    # Converte para base64
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")

    # Retorna no formato Data URI
    return f"data:image/png;base64,{img_str}"

# --- FIM NOVAS FUNÇÕES ---