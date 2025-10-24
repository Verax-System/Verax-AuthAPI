# auth_api/app/services/email_service.py
import asyncio
import traceback
from typing import Dict, Any
from loguru import logger
from app.core.config import settings

# --- NOVAS IMPORTAÇÕES (httpx e certifi já devem estar lá) ---
import httpx
import certifi
# --- FIM NOVAS IMPORTAÇÕES ---

# --- MUDANÇA 1: URL da API da Brevo ---
BREVO_API_URL = "https://api.brevo.com/v3/smtp/email"

# Helper assíncrono REESCRITO para usar HTTpx para a Brevo
async def send_email_http_api(
    email_to: str,
    subject: str,
    html_content: str
) -> bool:
    """
    Envia um email usando HTTpx manualmente para a API da Brevo.
    """
    # --- MUDANÇA 2: Verificar a nova API Key ---
    if not settings.BREVO_API_KEY:
        logger.error("BREVO_API_KEY não está configurada. Email não será enviado.")
        return False

    # --- MUDANÇA 3: Novo formato de Payload (JSON simples da Brevo) ---
    # Isto substitui a necessidade da biblioteca 'sendgrid.helpers.mail'
    message_payload = {
        "sender": {
            "name": settings.EMAIL_FROM_NAME or "Verax AuthAPI",
            "email": settings.EMAIL_FROM
        },
        "to": [
            {"email": email_to}
        ],
        "subject": subject,
        "htmlContent": html_content
    }

    # --- MUDANÇA 4: Novo formato de Header (api-key) ---
    headers = {
        "api-key": settings.BREVO_API_KEY, # Autenticação da Brevo
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        # 3. O transporte HTTpx permanece o mesmo (isto é bom!)
        transport = httpx.AsyncHTTPTransport(verify=certifi.where())
        
        async with httpx.AsyncClient(transport=transport) as client:
            logger.info(f"Enviando email para {email_to} via Brevo (HTTpx)...")
            response = await client.post(
                BREVO_API_URL, # Mudar para o URL da Brevo
                json=message_payload,
                headers=headers
            )

        # --- MUDANÇA 5: Processar a resposta da Brevo (201 Created) ---
        # A API v3 da Brevo retorna 201 Created em caso de sucesso
        if 200 <= response.status_code < 300:
            logger.info(f"Email aceito para envio para {email_to} via Brevo. Status: {response.status_code}")
            return True
        else:
            logger.error(f"Falha ao enviar email para {email_to} via Brevo (HTTpx).")
            logger.error(f"Status: {response.status_code}")
            logger.error(f"Body: {response.text}") # Usar .text para httpx
            return False

    except httpx.ConnectError as e:
        logger.error(f"Erro de conexão SSL/TLS ao enviar email (Brevo) para {email_to}: {e}")
        logger.error(f"Traceback completo: {traceback.format_exc()}")
        return False
    except Exception as e:
        logger.error(f"Erro CRÍTICO ao enviar email (Brevo HTTpx) para {email_to}: {e}")
        logger.error(f"Traceback completo: {traceback.format_exc()}")
        return False

# --- O RESTANTE DO ARQUIVO (FUNÇÕES DE CONTEÚDO) PERMANECE IGUAL ---
# Estas funções não precisam de mudança, pois elas apenas chamam 
# a função send_email_http_api (que acabámos de modificar).

# --- Função específica para email de verificação ---
async def send_verification_email(email_to: str, verification_token: str) -> bool:
    project_name = settings.EMAIL_FROM_NAME or "Sua Aplicação"
    subject = f"{project_name} - Verifique seu endereço de e-mail"
    verification_url = f"{settings.VERIFICATION_URL_BASE}/{verification_token}"

    html_content = f"""
    <html>
    <body>
        <p>Olá,</p>
        <p>Obrigado por se registrar em {project_name}. Por favor, clique no link abaixo para verificar seu e-mail:</p>
        <p><a href="{verification_url}">{verification_url}</a></p>
        <p>Se você não se registrou, por favor ignore este e-mail.</p>
        <p>Atenciosamente,<br>Equipe {project_name}</p>
    </body>
    </html>
    """

    return await send_email_http_api(
        email_to=email_to,
        subject=subject,
        html_content=html_content
    )

# --- Função específica para email de reset de senha ---
async def send_password_reset_email(email_to: str, reset_token: str) -> bool:
    project_name = settings.EMAIL_FROM_NAME or "Sua Aplicação"
    subject = f"{project_name} - Redefinição de Senha"
    reset_url = f"{settings.RESET_PASSWORD_URL_BASE}/{reset_token}"

    html_content = f"""
    <html>
    <body>
        <p>Olá,</p>
        <p>Recebemos uma solicitação para redefinir sua senha em {project_name}.</p>
        <p>Se foi você, clique no link abaixo para criar uma nova senha:</p>
        <p><a href="{reset_url}">{reset_url}</a></p>
        <p>Este link expirará em {settings.RESET_PASSWORD_TOKEN_EXPIRE_MINUTES} minutos.</p>
        <p>Se você não solicitou uma redefinição de senha, por favor ignore este e-mail.</p>
        <p>Atenciosamente,<br>Equipe {project_name}</p>
    </body>
    </html>
    """

    return await send_email_http_api(
        email_to=email_to,
        subject=subject,
        html_content=html_content
    )