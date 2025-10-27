import os
import time
import requests
import pytest
from dotenv import load_dotenv
from loguru import logger

# --- 1. Configuração ---
# Carrega as variáveis do seu arquivo .env
load_dotenv() 

# --- AJUSTE ESTES VALORES ---
EMAIL = "vitorhugolsenai6@gmail.com"
SENHA_CORRETA = "12345678Vl!"
SENHA_INCORRETA = "senhaerrada123!"
# Assume que você está rodando na porta 8001
BASE_URL = "http://localhost:8001" 
# ---------------------------

TOKEN_URL = f"{BASE_URL}/api/v1/auth/token"

# Lê as configurações de bloqueio do .env
#
try:
    MAX_ATTEMPTS = int(os.getenv("LOGIN_MAX_FAILED_ATTEMPTS", 5))
    LOCKOUT_MINUTES = int(os.getenv("LOGIN_LOCKOUT_MINUTES", 15))
except (ValueError, TypeError):
    logger.error("Não foi possível ler as configurações do .env. Usando padrões.")
    MAX_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15

logger.info(f"--- Iniciando Teste de Bloqueio de Conta ---")
logger.info(f"Usuário: {EMAIL}")
logger.info(f"Máximo de Tentativas: {MAX_ATTEMPTS}")
logger.info(f"Tempo de Bloqueio: {LOCKOUT_MINUTES} min")

def attempt_login(password: str) -> requests.Response:
    """Tenta fazer login e retorna a resposta."""
    # O endpoint /token espera dados de formulário (x-www-form-urlencoded)
    #
    # O 'requests' envia como formulário por padrão quando usamos o parâmetro 'data'
    payload = {
        "username": EMAIL,
        "password": password
    }
    try:
        response = requests.post(TOKEN_URL, data=payload)
        return response
    except requests.ConnectionError:
        logger.error(f"ERRO DE CONEXÃO: Não foi possível se conectar a {TOKEN_URL}.")
        logger.error("O servidor FastAPI está rodando na porta 8001?")
        pytest.fail("Connection error")

# --- 2. Fase de Bloqueio ---
logger.info(f"\n[FASE 1] Forçando o bloqueio com {MAX_ATTEMPTS} tentativas falhas...")
for i in range(MAX_ATTEMPTS):
    logger.info(f"Tentativa {i + 1}/{MAX_ATTEMPTS} (senha incorreta)...")
    response = attempt_login(SENHA_INCORRETA)
    logger.info(f" -> Status: {response.status_code}, Resposta: {response.json()}")
    
    if response.status_code != 400 or "Incorrect" not in response.json().get("detail", ""):
        logger.warning("Resposta inesperada. O teste pode falhar.")

logger.success(f"As {MAX_ATTEMPTS} tentativas falhas foram enviadas.")

# --- 3. Verificação do Bloqueio ---
logger.info("\n[FASE 2] Verificando se a conta está bloqueada...")
logger.info("Tentando logar com a SENHA CORRETA...")
response_locked = attempt_login(SENHA_CORRETA)
logger.info(f" -> Status: {response_locked.status_code}, Resposta: {response_locked.json()}")

if response_locked.status_code == 400 and "locked" in response_locked.json().get("detail", ""):
    logger.success("SUCESSO! A conta está bloqueada como esperado.")
else:
    logger.error("FALHA! A conta NÃO foi bloqueada após as tentativas.")
    pytest.fail("Account not locked after multiple failed attempts.")

# --- 4. Verificação do Desbloqueio ---
lockout_seconds = LOCKOUT_MINUTES * 60
logger.info(f"\n[FASE 3] Aguardando {LOCKOUT_MINUTES} min ({lockout_seconds}s) para o desbloqueio...")

# Adiciona 5 segundos de margem
wait_time = lockout_seconds + 5 
for i in range(wait_time):
    # Imprime um contador a cada 10 segundos
    if (wait_time - i) % 10 == 0 or i == wait_time - 1:
        print(f"   ...aguardando {wait_time - i}s restantes...", end="\r")
    time.sleep(1)

print("\nTempo de espera concluído.")

logger.info("\n[FASE 4] Verificando se a conta foi desbloqueada...")
logger.info("Tentando logar com a SENHA CORRETA novamente...")
response_unlocked = attempt_login(SENHA_CORRETA)

if response_unlocked.status_code == 200 and "access_token" in response_unlocked.json():
    logger.info(f" -> Status: {response_unlocked.status_code}, Resposta: {{'access_token': '...'}}")
    logger.success("SUCESSO! O login foi bem-sucedido após o tempo de bloqueio.")
    logger.info("--- Teste de Bloqueio de Conta Concluído ---")
else:
    logger.error(f"FALHA! O login falhou após o tempo de bloqueio.")
    logger.error(f" -> Status: {response_unlocked.status_code}, Resposta: {response_unlocked.json()}")
    pytest.fail("Login failed after lockout period.")