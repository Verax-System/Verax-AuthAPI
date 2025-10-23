# alembic/env.py
import asyncio
from logging.config import fileConfig

from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import create_async_engine

from alembic import context

# --- 1. Importar Base e Modelos ---
# Adicione sys.path para que o alembic encontre sua pasta 'app'
import os
import sys
from pathlib import Path
# Sobe dois níveis (alembic/ -> raiz) e adiciona ao path
sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.db.base import Base
from app.models import user # noqa F401
from app.models import refresh_token # noqa F401
# --- ADICIONAR NOVO MODELO ---
from app.models import mfa_recovery_code # noqa F401
# --- FIM ADIÇÃO ---
# --- Fim Importar Modelos ---


# --- 2. Carregar Configurações do App ---
from app.core.config import settings
# --- Fim Carregar Configurações ---


# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# --- 3. Definir o sqlalchemy.url dinamicamente ---
db_url = settings.DATABASE_URL
config.set_main_option("sqlalchemy.url", db_url)
# --- Fim MODIFICAÇÃO ---


# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
target_metadata = Base.metadata # --- 4. Apontar para a Base do nosso app ---


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True 
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    context.configure(
        connection=connection, 
        target_metadata=target_metadata,
        compare_type=True 
    )

    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    
    # --- 5. Configuração Assíncrona ---
    connectable = create_async_engine(
        config.get_main_option("sqlalchemy.url"),
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()
    # --- Fim Configuração Assíncrona ---


if context.is_offline_mode():
    run_migrations_offline()
else:
    # --- 6. Rodar no loop de eventos asyncio ---
    asyncio.run(run_migrations_online())
    # --- Fim asyncio ---