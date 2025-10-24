# auth_api/app/services/email_service.py
import asyncio
import traceback
from typing import Dict, Any
from loguru import logger
from app.core.config import settings
from datetime import datetime
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
            "name": settings.EMAIL_FROM_NAME or "Verax",
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
    # Obtém o nome do projeto a partir das configurações
    project_name = settings.EMAIL_FROM_NAME or "Nossa Aplicação"
    subject = f"Bem-vindo(a) a {project_name}! Confirme seu e-mail"
    
    # Obtém a URL de verificação a partir das configurações
    verification_url = f"{settings.VERIFICATION_URL_BASE}/{verification_token}"

    # --- Template HTML Profissional com CSS Inline ---
    # (Cores de exemplo: azul (#007bff) e cinza (#f4f4f4))
    html_content = f"""
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{subject}</title>
        <style>
            /* Estilos de reset (não essenciais, mas ajudam) */
            body, table, td, a {{ -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }}
            table, td {{ mso-table-lspace: 0pt; mso-table-rspace: 0pt; }}
            img {{ -ms-interpolation-mode: bicubic; border: 0; height: auto; line-height: 100%; outline: none; text-decoration: none; }}
            table {{ border-collapse: collapse !important; }}
            body {{ height: 100% !important; margin: 0 !important; padding: 0 !important; width: 100% !important; }}
        </style>
    </head>
    <body style="margin: 0 !important; padding: 0 !important; background-color: #f4f4f4;">
    
        <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
                <td align="center" style="background-color: #f4f4f4;">
                
                    <table border="0" cellpadding="0" cellspacing="0" width="600" style="width: 100%; max-width: 600px;">
                        
                        <tr>
                            <td align="center" valign="top" style="padding: 40px 10px 40px 10px;">
                                <h1 style="font-size: 32px; font-weight: 800; color: #333333; margin: 0; font-family: Arial, sans-serif;">
                                    {project_name}
                                </h1>
                            </td>
                        </tr>
                        
                        <tr>
                            <td align="center" style="background-color: #ffffff; padding: 40px 30px 40px 30px; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.05);">
                                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                    <tr>
                                        <td align="center" style="font-family: Arial, sans-serif; font-size: 24px; font-weight: bold; color: #333333;">
                                            Confirme seu endereço de e-mail
                                        </td>
                                    </tr>
                                    <tr>
                                        <td align="left" style="padding: 20px 0 30px 0; font-family: Arial, sans-serif; font-size: 16px; line-height: 24px; color: #555555;">
                                            <p style="margin: 0;">
                                                Olá,
                                            </p>
                                            <p style="margin: 15px 0 0 0;">
                                                Obrigado por se registrar em {project_name}. Estamos felizes em tê-lo(a) conosco.
                                                Para ativar sua conta e garantir sua segurança, por favor, clique no botão abaixo para verificar seu e-mail.
                                            </p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td align="center">
                                            <table border="0" cellspacing="0" cellpadding="0">
                                                <tr>
                                                    <td align="center" style="border-radius: 5px;" bgcolor="#007bff">
                                                        <a href="{verification_url}" target="_blank" style="font-size: 16px; font-family: Arial, sans-serif; color: #ffffff; text-decoration: none; border-radius: 5px; background-color: #007bff; padding: 15px 30px; border: 1px solid #007bff; display: inline-block; font-weight: bold;">
                                                            Verificar E-mail
                                                        </a>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td align="left" style="padding: 30px 0 0 0; font-family: Arial, sans-serif; font-size: 14px; line-height: 20px; color: #888888;">
                                            <p style="margin: 0;">
                                                Se o botão não funcionar, copie e cole o seguinte link no seu navegador:
                                            </p>
                                            <p style="margin: 10px 0 0 0; word-break: break-all;">
                                                <a href="{verification_url}" target="_blank" style="color: #007bff; text-decoration: underline;">{verification_url}</a>
                                            </p>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td align="left" style="padding: 30px 0 0 0; font-family: Arial, sans-serif; font-size: 14px; line-height: 20px; color: #888888;">
                                            <p style="margin: 0;">
                                                Se você não criou esta conta, por favor, ignore este e-mail com segurança.
                                            </p>
                                        </td>
                                    </tr>
                                </table>
                            </td>
                        </tr>
                        
                        <tr>
                            <td align="center" style="padding: 30px 10px 30px 10px; font-family: Arial, sans-serif; font-size: 12px; line-height: 18px; color: #888888;">
                                <p style="margin: 0;">© {datetime.now().year} {project_name}. Todos os direitos reservados.</p>
                                </td>
                        </tr>
                    </table>
                </td>
            </tr>
        </table>
    
    </body>
    </html>
    """

    # --- Adicionar o 'import datetime' no topo do ficheiro ---
    # (Certifique-se que 'from datetime import datetime' está no topo de app/services/email_service.py)

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