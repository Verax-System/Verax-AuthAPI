# tests/test_03_mfa_flows.py
from select import select
import pytest
from httpx import AsyncClient
from sqlalchemy import func
from sqlalchemy.ext.asyncio import AsyncSession
import pyotp  # Para gerar códigos OTP nos testes
import re

from app.models.mfa_recovery_code import MFARecoveryCode
from app.models.user import User
from app.crud import crud_mfa_recovery_code
from app.core import security

pytestmark = pytest.mark.asyncio

TEST_EMAIL = "mfa_user@example.com"
TEST_PASSWORD = "PasswordMfa123!"
WRONG_OTP = "000000"


async def create_and_login_user(
    async_client: AsyncClient, db_session: AsyncSession
) -> tuple[str, str, int]:
    """Helper: Cria, ativa e loga um usuário, retornando token de acesso, refresh e ID."""
    reg_response = await async_client.post(
        "/api/v1/users/",
        json={
            "email": TEST_EMAIL,
            "password": TEST_PASSWORD,
            "full_name": "MFA Test User",
        },
    )
    assert reg_response.status_code == 201
    user_id = reg_response.json()["id"]

    # Ativar
    user = await db_session.get(User, user_id)
    assert user is not None
    user.is_active = True
    user.is_verified = True
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)

    # Logar
    login_response = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert login_response.status_code == 200
    tokens = login_response.json()
    return tokens["access_token"], tokens["refresh_token"], user_id


async def test_mfa_full_flow(async_client: AsyncClient, db_session: AsyncSession):
    """Testa o fluxo completo de habilitar, verificar e desabilitar MFA."""
    access_token, _, user_id = await create_and_login_user(async_client, db_session)
    headers = {"Authorization": f"Bearer {access_token}"}

    # --- 1. Iniciar habilitação do MFA ---
    enable_response = await async_client.post(
        "/api/v1/auth/mfa/enable", headers=headers
    )
    assert enable_response.status_code == 200
    enable_data = enable_response.json()
    assert "otp_uri" in enable_data
    assert "qr_code_base64" in enable_data
    assert enable_data["qr_code_base64"].startswith("data:image/png;base64,")

    # Extrair o segredo OTP da URI para gerar códigos válidos no teste
    # Ex: otpauth://totp/Example:mfa_user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
    match = re.search(r"secret=([A-Z2-7=]+)", enable_data["otp_uri"])
    assert match is not None
    otp_secret = match.group(1)
    assert otp_secret is not None

    # Verificar no BD se o segredo pendente foi salvo
    user = await db_session.get(User, user_id)
    assert user.otp_secret == otp_secret
    assert user.is_mfa_enabled is False

    # --- 2. Confirmar MFA com código OTP correto ---
    totp = pyotp.TOTP(otp_secret)
    current_otp = totp.now()

    confirm_response = await async_client.post(
        "/api/v1/auth/mfa/confirm", headers=headers, json={"otp_code": current_otp}
    )
    assert confirm_response.status_code == 200
    confirm_data = confirm_response.json()
    assert confirm_data["user"]["is_mfa_enabled"] is True
    assert "recovery_codes" in confirm_data
    assert len(confirm_data["recovery_codes"]) == 10
    plain_recovery_codes = confirm_data["recovery_codes"]

    # Verificar no BD se MFA está ativo e códigos de recuperação foram criados
    await db_session.refresh(user)
    assert user.is_mfa_enabled is True
    assert user.otp_secret == otp_secret  # Segredo permanece
    recovery_codes_db = await crud_mfa_recovery_code.get_valid_recovery_code(
        db_session, user=user, plain_code=plain_recovery_codes[0]
    )
    assert recovery_codes_db is not None  # Pelo menos um existe e é válido

    # --- 3. Fazer Logout (simulado) e tentar Logar novamente ---
    # Login agora deve pedir MFA
    login_response_mfa = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert login_response_mfa.status_code == 200
    mfa_challenge_data = login_response_mfa.json()
    assert mfa_challenge_data["detail"] == "MFA verification required"
    assert "mfa_challenge_token" in mfa_challenge_data
    mfa_challenge_token = mfa_challenge_data["mfa_challenge_token"]

    # --- 4. Verificar MFA com OTP incorreto (deve falhar) ---
    verify_wrong_response = await async_client.post(
        "/api/v1/auth/mfa/verify",
        json={"mfa_challenge_token": mfa_challenge_token, "otp_code": WRONG_OTP},
    )
    assert verify_wrong_response.status_code == 400
    assert "Código OTP inválido" in verify_wrong_response.json()["detail"]

    # --- 5. Verificar MFA com OTP correto (deve retornar tokens) ---
    current_otp_login = totp.now()
    verify_response = await async_client.post(
        "/api/v1/auth/mfa/verify",
        json={
            "mfa_challenge_token": mfa_challenge_token,
            "otp_code": current_otp_login,
        },
    )
    assert verify_response.status_code == 200
    final_tokens = verify_response.json()
    assert "access_token" in final_tokens
    assert "refresh_token" in final_tokens

    # Decodificar o access token para verificar o claim 'amr'
    decoded_access = security.decode_access_token(final_tokens["access_token"])
    assert decoded_access is not None
    assert "amr" in decoded_access
    assert decoded_access["amr"] == ["pwd", "mfa"]  # Verifica se MFA está no AMR

    # --- 6. Usar um Código de Recuperação ---
    # Primeiro, logar de novo para obter um challenge token
    login_response_recovery = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    mfa_challenge_token_recovery = login_response_recovery.json()["mfa_challenge_token"]

    # Tentar com código de recuperação inválido
    recovery_wrong_response = await async_client.post(
        "/api/v1/auth/mfa/verify-recovery",
        json={
            "mfa_challenge_token": mfa_challenge_token_recovery,
            "recovery_code": "invalid-code",
        },
    )
    assert recovery_wrong_response.status_code == 400
    assert (
        "Código de recuperação inválido ou já utilizado"
        in recovery_wrong_response.json()["detail"]
    )

    # Tentar com um código válido
    valid_recovery_code = plain_recovery_codes[0]
    recovery_response = await async_client.post(
        "/api/v1/auth/mfa/verify-recovery",
        json={
            "mfa_challenge_token": mfa_challenge_token_recovery,
            "recovery_code": valid_recovery_code,
        },
    )
    assert recovery_response.status_code == 200
    recovery_tokens = recovery_response.json()
    assert "access_token" in recovery_tokens

    # Verificar no BD se o código foi marcado como usado
    code_in_db_after = await crud_mfa_recovery_code.get_valid_recovery_code(
        db_session, user=user, plain_code=valid_recovery_code
    )
    assert code_in_db_after is None  # Não deve mais ser encontrado como válido

    # Tentar usar o mesmo código de novo (deve falhar)
    login_response_reuse = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    mfa_challenge_token_reuse = login_response_reuse.json()["mfa_challenge_token"]
    reuse_response = await async_client.post(
        "/api/v1/auth/mfa/verify-recovery",
        json={
            "mfa_challenge_token": mfa_challenge_token_reuse,
            "recovery_code": valid_recovery_code,
        },
    )
    assert reuse_response.status_code == 400
    assert (
        "Código de recuperação inválido ou já utilizado"
        in reuse_response.json()["detail"]
    )

    # --- 7. Desabilitar MFA ---
    # Usar o token obtido pelo código de recuperação
    headers_recovery = {"Authorization": f"Bearer {recovery_tokens['access_token']}"}
    current_otp_disable = totp.now()

    # Tentar desabilitar com código OTP errado
    disable_wrong_response = await async_client.post(
        "/api/v1/auth/mfa/disable",
        headers=headers_recovery,
        json={"otp_code": WRONG_OTP},
    )
    assert disable_wrong_response.status_code == 400
    assert "Código OTP inválido" in disable_wrong_response.json()["detail"]

    # Tentar desabilitar com código OTP correto
    disable_response = await async_client.post(
        "/api/v1/auth/mfa/disable",
        headers=headers_recovery,
        json={"otp_code": current_otp_disable},
    )
    assert disable_response.status_code == 200
    disable_data = disable_response.json()
    assert disable_data["is_mfa_enabled"] is False

    # Verificar no BD
    await db_session.refresh(user)
    assert user.is_mfa_enabled is False
    assert user.otp_secret is None
    # Verificar se os códigos de recuperação foram apagados (contagem deve ser 0)
    stmt = select(func.count(MFARecoveryCode.id)).where(
        MFARecoveryCode.user_id == user_id
    )
    count_result = await db_session.execute(stmt)
    assert count_result.scalar_one() == 0

    # --- 8. Logar novamente (MFA não deve ser pedido) ---
    login_final_response = await async_client.post(
        "/api/v1/auth/token", data={"username": TEST_EMAIL, "password": TEST_PASSWORD}
    )
    assert login_final_response.status_code == 200
    final_login_data = login_final_response.json()
    assert "access_token" in final_login_data
    assert "mfa_challenge_token" not in final_login_data  # Garante que não pediu MFA
