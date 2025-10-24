# tests/test_12_email_service.py
import pytest
from unittest.mock import patch, AsyncMock
import httpx # Para simular erros httpx
import logging # Manter para o caplog de outros testes (se houver)

from app.services import email_service
from app.core.config import settings

pytestmark = pytest.mark.asyncio

TEST_EMAIL_TO = "recipient@example.com"
TEST_TOKEN = "test_token_123"

@pytest.fixture(autouse=True)
def override_settings(monkeypatch):
    """Ensure necessary settings are present for email tests."""
    monkeypatch.setattr(settings, "SENDGRID_API_KEY", "test_sendgrid_key")
    monkeypatch.setattr(settings, "EMAIL_FROM", "sender@test.com")
    monkeypatch.setattr(settings, "EMAIL_FROM_NAME", "Test Sender")
    monkeypatch.setattr(settings, "VERIFICATION_URL_BASE", "http://test.com/verify")
    monkeypatch.setattr(settings, "RESET_PASSWORD_URL_BASE", "http://test.com/reset")
    monkeypatch.setattr(settings, "RESET_PASSWORD_TOKEN_EXPIRE_MINUTES", 30)


@pytest.mark.asyncio
async def test_send_verification_email_success():
    """Test successful sending of verification email content construction."""
    with patch("app.services.email_service.httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        # Mock successful response (202 Accepted)
        mock_response = httpx.Response(202, text="Accepted")
        mock_post.return_value = mock_response

        result = await email_service.send_verification_email(TEST_EMAIL_TO, TEST_TOKEN)

        assert result is True
        mock_post.assert_awaited_once()
        
        # Check payload basics
        call_args = mock_post.await_args.args
        call_kwargs = mock_post.await_args.kwargs
        
        assert call_args[0] == email_service.SENDGRID_API_URL # URL é posicional
        payload = call_kwargs['json']
        
        assert payload['personalizations'][0]['to'][0]['email'] == TEST_EMAIL_TO
        assert payload['from']['email'] == settings.EMAIL_FROM
        assert "Verifique seu endereço de e-mail" in payload['subject']
        expected_url = f"{settings.VERIFICATION_URL_BASE}/{TEST_TOKEN}"
        assert expected_url in payload['content'][0]['value'] # Check if URL is in HTML

@pytest.mark.asyncio
async def test_send_password_reset_email_success():
    """Test successful sending of password reset email content construction."""
    with patch("app.services.email_service.httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_response = httpx.Response(202, text="Accepted")
        mock_post.return_value = mock_response

        result = await email_service.send_password_reset_email(TEST_EMAIL_TO, TEST_TOKEN)

        assert result is True
        mock_post.assert_awaited_once()
        
        call_args = mock_post.await_args.args
        call_kwargs = mock_post.await_args.kwargs
        payload = call_kwargs['json']
        
        assert call_args[0] == email_service.SENDGRID_API_URL
        assert payload['personalizations'][0]['to'][0]['email'] == TEST_EMAIL_TO
        assert "Redefinição de Senha" in payload['subject']
        expected_url = f"{settings.RESET_PASSWORD_URL_BASE}/{TEST_TOKEN}"
        assert expected_url in payload['content'][0]['value']
        assert f"{settings.RESET_PASSWORD_TOKEN_EXPIRE_MINUTES} minutos" in payload['content'][0]['value']


@pytest.mark.asyncio
async def test_send_email_http_api_no_key(monkeypatch): # <-- Removido caplog
    """Test email sending failure when API key is missing."""
    monkeypatch.setattr(settings, "SENDGRID_API_KEY", "") # Simulate missing key
    
    # --- CORREÇÃO (Patch Loguru) ---
    # Em vez de caplog, fazemos patch no logger do loguru diretamente
    with patch("app.services.email_service.logger.error") as mock_logger_error:
        result = await email_service.send_email_http_api(TEST_EMAIL_TO, "Subject", "<p>Content</p>")
    # --- FIM CORREÇÃO ---

    assert result is False
    # Verificamos se o mock do logger foi chamado com a mensagem esperada
    mock_logger_error.assert_called_once_with(
        "SENDGRID_API_KEY não está configurada. Email não será enviado."
    )


@pytest.mark.asyncio
async def test_send_email_http_api_sendgrid_error():
    """Test email sending failure when SendGrid returns an error."""
    with patch("app.services.email_service.httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        # Mock failed response (e.g., 401 Unauthorized)
        mock_response = httpx.Response(401, text="Unauthorized", request=httpx.Request("POST", email_service.SENDGRID_API_URL))
        mock_post.return_value = mock_response

        # Também fazemos patch no logger aqui para evitar poluir o console do teste
        with patch("app.services.email_service.logger.error"):
            result = await email_service.send_email_http_api(TEST_EMAIL_TO, "Subject", "<p>Content</p>")

        assert result is False
        mock_post.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_email_http_api_connect_error():
    """Test email sending failure due to connection error."""
    with patch("app.services.email_service.httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        # Simulate a connection error
        mock_post.side_effect = httpx.ConnectError("Connection refused")

        # Patch no logger para evitar poluição
        with patch("app.services.email_service.logger.error"):
            result = await email_service.send_email_http_api(TEST_EMAIL_TO, "Subject", "<p>Content</p>")

        assert result is False
        mock_post.assert_awaited_once()