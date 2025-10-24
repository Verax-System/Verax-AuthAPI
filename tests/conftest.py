import os
os.environ["TESTING"] = "true"
import pytest
import asyncio
from typing import AsyncGenerator

# --- MODIFICAÇÃO: Importar ASGITransport ---
from httpx import AsyncClient, ASGITransport
# --- FIM MODIFICAÇÃO ---

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.db.base import Base
from main import app # Esta importação (da raiz) está CORRETA
from app.api.dependencies import get_db

# --- CONFIGURAÇÃO DO BANCO DE DADOS DE TESTE ---
TEST_DATABASE_URL = "sqlite+aiosqlite:///./test.db"

@pytest.fixture(scope="session")
def async_engine():
    engine = create_async_engine(TEST_DATABASE_URL)
    yield engine
    engine.sync_engine.dispose()
    try:
        os.remove("test.db")
    except PermissionError:
        print("Aviso: não foi possível remover 'test.db'. Pode estar em uso.")

@pytest.fixture(scope="session")
def test_session_local(async_engine):
    TestSessionLocal = async_sessionmaker(
        bind=async_engine, 
        class_=AsyncSession, 
        expire_on_commit=False
    )
    yield TestSessionLocal

@pytest.fixture(scope="function", autouse=True)
async def db_session(async_engine, test_session_local):
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
    
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db

    # --- MODIFICAÇÃO: Usar ASGITransport ---
    # Em vez de app=app, passamos o 'app' para o transporte
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
    # --- FIM MODIFICAÇÃO ---
        
    app.dependency_overrides.pop(get_db, None)