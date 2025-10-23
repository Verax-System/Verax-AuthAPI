# ---- Builder Stage ----
# (Esta parte permanece a mesma)
FROM python:3.10-slim AS builder

WORKDIR /app

# Instala apenas as dependências de build (se houver) e de produção
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia o código da aplicação
COPY . .

# ---- Final Stage (Otimizado para Produção) ----
FROM python:3.10-slim

WORKDIR /app

# 1. Criar um usuário não-root para segurança
RUN addgroup --system app && adduser --system --group app

# 2. Copiar apenas os arquivos necessários do builder
# Copia as dependências instaladas
COPY --from=builder /usr/local/lib/python3.10/site-packages /usr/local/lib/python3.10/site-packages
# Copia a aplicação
COPY --from=builder /app .

# 3. Definir permissões
RUN chown -R app:app /app

# 4. Mudar para o usuário não-root
USER app

EXPOSE 8001

# 5. Comando de Produção (Gunicorn + Uvicorn)
# Substitui o "uvicorn --reload" do docker-compose
# -w 4: Inicia 4 processos "workers" (ajuste conforme os CPUs do seu servidor)
# -k uvicorn.workers.UvicornWorker: Usa uvicorn como a classe de worker
# --bind 0.0.0.0:8001: Expõe na porta 8001
CMD ["gunicorn", "main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8001"]