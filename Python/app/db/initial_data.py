# auth_api/app/db/initial_data.py
import asyncio
import logging
import os # Import os for the windows check

# Configuração básica de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 1. Importar a Base
from app.db.base import Base
# --- CORRECTION: Import the function that gets the engine ---
from app.db.session import get_async_engine, dispose_engine # Import get_async_engine
# --- END CORRECTION ---

# 2. Importar TODOS os seus modelos para que Base.metadata os conheça
from app.models import user # noqa F401
from app.models.refresh_token import RefreshToken # noqa F401
# Adicione aqui importações para outros modelos que você criar no futuro

async def init_db() -> None:
    logger.info("Iniciando a recriação do banco de dados (DROP ALL / CREATE ALL)...")
    # --- CORRECTION: Get the engine instance by calling the function ---
    engine = get_async_engine()
    # --- END CORRECTION ---
    async with engine.begin() as conn:
        logger.info("Removendo todas as tabelas existentes (se houver)...")
        await conn.run_sync(Base.metadata.drop_all)
        logger.info("Tabelas removidas.")

        logger.info("Criando todas as tabelas definidas nos modelos...")
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Tabelas criadas com sucesso.")

    logger.info("Processo de inicialização do banco de dados concluído.")
    # Garante que a engine seja descartada corretamente ao final
    await dispose_engine() # Call the dispose function from session.py

async def main() -> None:
    await init_db()

if __name__ == "__main__":
    # Define a política de loop de eventos do asyncio (importante no Windows)
    if os.name == 'nt': # Verifica se é Windows
        # Check if the policy is already set or needed
        try:
            asyncio.get_event_loop_policy()
        except asyncio.MissingEventLoopPolicyError:
             asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Ocorreu um erro durante a inicialização do banco de dados: {e}")
        import traceback
        logger.error(traceback.format_exc())