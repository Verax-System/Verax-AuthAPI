# auth_api/app/db/session.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.core.config import settings  # Keep importing settings
from typing import AsyncGenerator, Optional  # Add Optional
from sqlalchemy.ext.asyncio import AsyncEngine  # For type hinting

# --- Delay Engine and Session Creation ---
_async_engine: Optional[AsyncEngine] = None
_AsyncSessionLocal: Optional[sessionmaker] = None


def get_async_engine() -> AsyncEngine:
    """Creates the engine if it doesn't exist yet."""
    global _async_engine
    if _async_engine is None:
        try:
            # --- MODIFICAÇÃO: Usar a DATABASE_URL diretamente ---
            # O usuário agora é responsável por fornecer o driver async correto no .env
            # Ex: "postgresql+asyncpg://...", "sqlite+aiosqlite:///...", "mysql+aiomysql://..."
            db_url = settings.DATABASE_URL
            if not db_url:
                raise AttributeError("DATABASE_URL não definida no .env")
            # --- FIM MODIFICAÇÃO ---

            _async_engine = create_async_engine(
                db_url,
                pool_pre_ping=True,
                echo=False,  # Change to True to see SQL logs
            )
        except AttributeError:
            raise RuntimeError(
                "DATABASE_URL not loaded from settings. Check .env file and config.py"
            )
        except Exception as e:
            raise RuntimeError(f"Could not create async engine: {e}")
    return _async_engine


def get_session_local() -> sessionmaker:
    """Creates the session factory if it doesn't exist yet."""
    global _AsyncSessionLocal
    if _AsyncSessionLocal is None:
        engine = get_async_engine()  # Ensure engine is created first
        _AsyncSessionLocal = sessionmaker(
            bind=engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autocommit=False,
            autoflush=False,
        )  # type: ignore # Ignorar erro de overload do sessionmaker
    return _AsyncSessionLocal


# --- End Delay ---


# Dependency function now ensures session factory is created before use
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    SessionLocal = get_session_local()  # Get or create the session factory
    async with SessionLocal() as db:
        try:
            yield db
        finally:
            await db.close()


# Optional: Function to dispose engine on shutdown (add to FastAPI shutdown event)
async def dispose_engine():
    global _async_engine
    if _async_engine:
        await _async_engine.dispose()
        _async_engine = None
