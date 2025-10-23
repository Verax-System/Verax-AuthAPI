import os
import pytest
import asyncio
from typing import AsyncGenerator

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.db.base import Base
from app.main import app
from app.api.dependencies import get_db

# --- CONFIGURAÇÃO DO BANCO DE DADOS DE TESTE ---
# Usar um banco de dados SQLite em arquivo para testes
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

# Criar uma engine de teste (escopo de "sessão" - dura todos os testes)
@pytest.fixture(scope="session")
def async_engine():
    engine = create_async_engine(TEST_DATABASE_URL)
    yield engine
    engine.sync_engine.dispose() # Descartar a engine no final
    os.remove("test.db") # Limpar o arquivo do BD de teste

# Criar a fábrica de sessões de teste (escopo de "sessão")
@pytest.fixture(scope="session")
def test_session_local(async_engine):
    TestSessionLocal = async_sessionmaker(
        bind=async_engine, 
        class_=AsyncSession, 
        expire_on_commit=False
    )
    yield TestSessionLocal

# Fixture principal do banco de dados (escopo de "função" - roda para CADA teste)
@pytest.fixture(scope="function", autouse=True)
async def db_session(async_engine, test_session_local):
    """
    Fixture que cria um banco de dados limpo e uma sessão
    para cada função de teste.
    """
    async with async_engine.begin() as conn:
        # Criar todas as tabelas
        await conn.run_sync(Base.metadata.create_all)

    # Iniciar uma sessão/transação
    async with test_session_local() as session:
        yield session # <-- O TESTE RODA AQUI
        
        # Limpar a sessão
        await session.close()

    async with async_engine.begin() as conn:
        # Limpar todas as tabelas para o próximo teste
        await conn.run_sync(Base.metadata.drop_all)


# --- CONFIGURAÇÃO DO CLIENTE HTTP DE TESTE ---

@pytest.fixture(scope="function")
async def async_client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """
    Fixture que cria um cliente HTTP assíncrono (httpx) e
    sobrescreve a dependência get_db para usar a sessão de teste.
    """
    
    # Função "falsa" que substitui o get_db original
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        try:
            yield db_session
        finally:
            await db_session.close()

    # Aplicar a substituição no app FastAPI
    app.dependency_overrides[get_db] = override_get_db

    # Criar e retornar o cliente
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
        
    # Limpar a substituição
    app.dependency_overrides.pop(get_db, None)