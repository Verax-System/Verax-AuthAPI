# auth_api/app/services/email_service.py
import asyncio
import traceback
from typing import Dict, Any
from loguru import logger
from sendgrid.helpers.mail import Mail, From, To, Content
from app.core.config import settings

# --- NOVAS IMPORTAÇÕES ---
import httpx
import certifi
# --- FIM NOVAS IMPORTAÇÕES ---

# URL da API SendGrid
SENDGRID_API_URL = "https://api.sendgrid.com/v3/mail/send"

# Helper assíncrono REESCRITO para usar HTTpx
async def send_email_http_api(
    email_to: str,
    subject: str,
    html_content: str
) -> bool:
    """
    Envia um email usando HTTpx manualmente, o que lida melhor
    com certificados SSL (usando 'certifi').
    """
    if not settings.SENDGRID_API_KEY:
        logger.error("SENDGRID_API_KEY não está configurada. Email não será enviado.")
        return False

    # 1. Usar a biblioteca sendgrid apenas para construir o payload
    message = Mail(
        from_email=From(settings.EMAIL_FROM, settings.EMAIL_FROM_NAME),
        to_emails=To(email_to),
        subject=subject,
        html_content=Content("text/html", html_content)
    )
    # Obter o payload JSON que a biblioteca sendgrid teria enviado
    message_payload = message.get()

    # 2. Preparar a requisição manual com httpx
    headers = {
        "Authorization": f"Bearer {settings.SENDGRID_API_KEY}",
        "Content-Type": "application/json"
    }

    try:
        # 3. Criar um transporte que USA EXPLICITAMENTE os certificados do certifi
        # Esta é a correção definitiva para [SSL: CERTIFICATE_VERIFY_FAILED]
        transport = httpx.AsyncHTTPTransport(verify=certifi.where())
        
        async with httpx.AsyncClient(transport=transport) as client:
            logger.info(f"Enviando email para {email_to} via HTTpx (com certifi)...")
            response = await client.post(
                SENDGRID_API_URL,
                json=message_payload,
                headers=headers
            )

        # 4. Processar a resposta do httpx
        # A API v3 do SendGrid retorna 202 Accepted em caso de sucesso
        if 200 <= response.status_code < 300:
            logger.info(f"Email aceito para envio para {email_to} via SendGrid. Status: {response.status_code}")
            return True
        else:
            logger.error(f"Falha ao enviar email para {email_to} via HTTpx.")
            logger.error(f"Status: {response.status_code}")
            logger.error(f"Body: {response.text}") # Usar .text para httpx
            return False

    except httpx.ConnectError as e:
        logger.error(f"Erro de conexão SSL/TLS ao enviar email para {email_to}: {e}")
        logger.error("Isso confirma o problema de SSL. Verifique se 'certifi' está atualizado.")
        logger.error(f"Traceback completo: {traceback.format_exc()}")
        return False
    except Exception as e:
        logger.error(f"Erro CRÍTICO ao enviar email (HTTpx) para {email_to}: {e}")
        logger.error(f"Traceback completo: {traceback.format_exc()}")
        return False

# --- O RESTANTE DO ARQUIVO (FUNÇÕES DE CONTEÚDO) PERMANECE IGUAL ---

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