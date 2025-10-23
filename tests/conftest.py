import os
import pytest
# import asyncio # <-- REMOVIDO F401
from typing import AsyncGenerator

from httpx import AsyncClient
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from app.db.base import Base
from app.main import app
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
        bind=async_engine,
        class_=AsyncSession,
        expire_on_commit=False
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
    """Cria cliente httpx e sobrescreve get_db."""
    async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
        try:
            yield db_session
        finally:
            await db_session.close()

    app.dependency_overrides[get_db] = override_get_db

    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client

    app.dependency_overrides.pop(get_db, None)