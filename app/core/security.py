from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from passlib.context import CryptContext  # type: ignore
from jose import jwt, JWTError  # type: ignore
from .config import settings

# import secrets # <-- REMOVED
from app.models.user import User as UserModel
import pyotp  # type: ignore
import qrcode  # type: ignore
import io
import base64
from loguru import logger

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --- VERIFICAÇÃO E HASH (EXISTENTES) ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        # Limita o tamanho da senha ANTES de passar para o bcrypt (evita erros > 72 bytes)
        password_bytes = plain_password.encode("utf-8")[:72]
        return pwd_context.verify(password_bytes, hashed_password)
    except Exception:
        # Consider logging the exception here for debugging potential issues
        return False


def get_password_hash(password: str) -> str:
    # Limita o tamanho da senha ANTES de passar para o bcrypt
    password_bytes = password.encode("utf-8")[:72]
    return pwd_context.hash(password_bytes)


# --- NOVAS FUNÇÕES HELPER PARA RECOVERY CODES ---
# Reutilizar as funções de senha para os códigos de recuperação
def verify_recovery_code(plain_code: str, hashed_code: str) -> bool:
    # Códigos de recuperação são mais curtos, não precisam do limite de 72 bytes
    try:
        return pwd_context.verify(plain_code, hashed_code)
    except Exception:
        return False


def hash_recovery_code(plain_code: str) -> str:
    return pwd_context.hash(plain_code)


# --- FIM NOVAS FUNÇÕES ---


# --- Funções JWT (com Claims OIDC) ---
def create_access_token(
    user: UserModel,
    requested_scopes: Optional[list[str]] = None,
    mfa_passed: bool = True,  # NOVO: Indica se o MFA foi verificado nesta sessão
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
        "amr": ["pwd", "mfa"] if user.is_mfa_enabled and mfa_passed else ["pwd"],
        **({"name": user.full_name} if user.full_name else {}),
    }
    if user.custom_claims and requested_scopes:
        for scope in requested_scopes:
            if scope in user.custom_claims and scope not in to_encode:
                to_encode[scope] = user.custom_claims.get(scope)
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM
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
            issuer=settings.JWT_ISSUER,
            options={"verify_iss": True, "verify_aud": True},
        )
        return payload
    except JWTError as e:
        logger.warning(f"Falha ao decodificar Access Token: {e}")  # Log útil
        return None


def create_refresh_token(data: Dict[str, Any]) -> tuple[str, datetime]:
    to_encode = data.copy()
    expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update(
        {"iss": settings.JWT_ISSUER, "exp": expire, "token_type": "refresh"}
    )
    encoded_jwt = jwt.encode(
        to_encode, settings.REFRESH_SECRET_KEY, algorithm=settings.ALGORITHM
    )
    return encoded_jwt, expire.replace(tzinfo=None)


def decode_refresh_token(token: str) -> Dict | None:
    try:
        payload = jwt.decode(
            token,
            settings.REFRESH_SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            issuer=settings.JWT_ISSUER,
            options={"verify_iss": True, "verify_aud": False},
        )
        if payload.get("token_type") != "refresh":
            return None
        return payload
    except JWTError as e:
        logger.warning(f"Falha ao decodificar Refresh Token: {e}")
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
        "nbf": datetime.now(timezone.utc),
        "sub": email,
        "token_type": "password_reset",
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
            issuer=settings.JWT_ISSUER,
            options={"verify_iss": True, "verify_aud": True},
        )
        if payload.get("token_type") != "password_reset" or "sub" not in payload:
            return None
        return payload
    except JWTError as e:
        logger.warning(f"Falha ao decodificar Password Reset Token: {e}")
        return None


# --- NOVAS FUNÇÕES MFA/OTP ---


def generate_otp_secret() -> str:
    """Gera um novo segredo OTP seguro (base32)."""
    return pyotp.random_base32()


def generate_otp_uri(secret: str, email: str, issuer_name: str) -> str:
    """
    Gera uma URI 'otpauth://' que pode ser usada por apps autenticadores.
    """
    safe_issuer_name = issuer_name.replace(":", "")
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email, issuer_name=safe_issuer_name
    )


def verify_otp_code(secret: str, code: str) -> bool:
    """
    Verifica se um código OTP é válido para o segredo fornecido.
    Permite uma pequena janela de tempo para sincronização.
    """
    if not secret:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_qr_code_base64(otp_uri: str) -> str:
    """Gera um QR Code a partir da URI OTP e retorna como imagem base64."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(otp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{img_str}"


# --- FIM NOVAS FUNÇÕES ---
