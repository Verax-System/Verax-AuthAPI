import os
import pytest

# import asyncio # <-- REMOVIDO F401
from typing import AsyncGenerator

from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.db.base import Base
from main import app
from app.api.dependencies import get_db

# --- CONFIGURAÇÃO DO BANCO DE DADOS DE TESTE ---
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"


@pytest.fixture(scope="session")
def async_engine():
    engine = create_async_engine(TEST_DATABASE_URL)
    yield engine
    engine.sync_engine.dispose()
    if os.path.exists("test.db"):
        os.remove("test.db")


@pytest.fixture(scope="session")
def test_session_local(async_engine):
    TestSessionLocal = async_sessionmaker(
        bind=async_engine, class_=AsyncSession, expire_on_commit=False
    )
    yield TestSessionLocal


@pytest.fixture(scope="function", autouse=True)
async def db_session(async_engine, test_session_local):
    """Cria BD e sessão limpos para cada teste."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with test_session_local() as session:
        yield session
        await session.close()

    async with async_engine.begin() as conn:
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
        # Apenas entregue a sessão. Não a feche aqui.
        # A fixture 'db_session' é quem vai fechá-la no final do teste.
        yield db_session

    # Aplicar a substituição no app FastAPI
    app.dependency_overrides[get_db] = override_get_db

    # Criar e retornar o cliente
    # (Estou assumindo que você já aplicou a correção do ASGITransport)
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client

    # Limpar a substituição
    app.dependency_overrides.pop(get_db, None)
