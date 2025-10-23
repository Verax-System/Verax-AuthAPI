# auth_api/app/db/initial_data.py
import asyncio
import logging
import os # Import os for the windows check

# --- MOVIDOS PARA O TOPO E402 ---
from app.db.base import Base
from app.db.session import get_async_engine, dispose_engine
from app.models import user # noqa F401
from app.models.refresh_token import RefreshToken # noqa F401
from app.models.mfa_recovery_code import MFARecoveryCode # noqa F401
# --- FIM MOVIDOS ---

# Configuração básica de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Imports que estavam aqui movidos para o topo

async def init_db() -> None:
    logger.info("Iniciando a recriação do banco de dados (DROP ALL / CREATE ALL)...")
    engine = get_async_engine()
    async with engine.begin() as conn:
        logger.info("Removendo todas as tabelas existentes (se houver)...")
        await conn.run_sync(Base.metadata.drop_all)
        logger.info("Tabelas removidas.")

        logger.info("Criando todas as tabelas definidas nos modelos...")
        await conn.run_sync(Base.metadata.create_all)
        logger.info("Tabelas criadas com sucesso.")

    logger.info("Processo de inicialização do banco de dados concluído.")
    await dispose_engine()

async def main() -> None:
    await init_db()

if __name__ == "__main__":
    if os.name == 'nt':
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