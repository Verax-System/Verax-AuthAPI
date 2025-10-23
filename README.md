<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg?style=for-the-badge&logo=python" alt="Python Version">
  <img src="https://img.shields.io/badge/Rust-1.60+-orange.svg?style=for-the-badge&logo=rust" alt="Rust Version">
  <img src="https://img.shields.io/badge/FastAPI-0.119.1-teal.svg?style=for-the-badge&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Axum-0.8.6-black.svg?style=for-the-badge" alt="Axum">
  <a href="https://github.com/SEU_USUARIO/SEU_REPOSITORIO/blob/main/LICENSE" target="_blank">
      <img src="https://img.shields.io/github/license/Verax-System/Verax-AuthAPI?style=for-the-badge&color=brightgreen" alt="License">
  </a>
</p>

# Verax AuthAPI

Um serviço de identidade agnóstico, seguro e flexível. Construído com FastAPI e PostgreSQL para servir como um provedor de identidade (IdP) centralizado para qualquer aplicação.

Este projeto agora inclui a implementação original robusta em **Python (FastAPI)**, com suporte completo a **MFA (Autenticação de Múltiplos Fatores)**, e também uma **reescrita completa em Rust (Axum)** para máxima performance.

## 💡 Conceito Central: Autenticação vs. Autorização

Esta API foi projetada com uma filosofia fundamental: a rigorosa separação entre **Autenticação** (provar quem você é) e **Autorização** (definir o que você pode fazer).

### Esta API (Auth API) cuida da Autenticação:

* Gerencia com segurança o registro, login e dados do usuário.
* Verifica identidades via email, reset de senha, bloqueio de conta e **MFA (TOTP)**.
* Fornece um "cofre" de `custom_claims` (claims customizados) flexível para cada usuário.
* Emite tokens JWT contendo Claims Padrão OIDC (`iss`, `aud`, `sub`, `email`, `amr`, etc.) para maior compatibilidade.

### Sua Aplicação (ex: VR Sales) cuida da Autorização:

* Você define quais *roles* ou *permissions* existem no seu sistema.
* Você usa a API de Gerenciamento (`/mgmt`) para escrever esses dados no `custom_claims` do usuário na API Auth (ex: `{"roles": ["admin"], "store_id": 123}`).
* Você solicita esses dados (`scopes`) durante o login para que sejam injetados no JWT.
* Sua aplicação valida o JWT e interpreta os claims (`amr`, `roles`, `store_id`) para aplicar sua lógica de negócios.

Este design oferece flexibilidade total, permitindo que qualquer sistema utilize um serviço de identidade robusto enquanto mantém controle total sobre sua própria lógica de negócios e permissões.

---

## ✨ Features

### Implementação Principal (Python / FastAPI)

* ✅ **Gerenciamento de Identidade:** Registro de usuário e recuperação de perfil (`/users/`, `/me`).
* ✅ **Fluxo de Tokens (JWT):** Login com `access_token` e `refresh_token` (com rotação).
* ✅ **Claims JWT Padrão OIDC:** Tokens incluem `iss`, `aud`, `sub`, `iat`, `exp`, `email`, `email_verified`, `name` e `amr` (Authentication Methods Reference).
* ✅ **Autenticação de Múltiplos Fatores (MFA/TOTP):**
    * Fluxo completo para Habilitar, Confirmar e Desabilitar MFA (via Google Authenticator, Authy, etc.).
    * Geração de QR Code (Base64) e URI `otpauth://`.
    * Verificação MFA (2-step) no login, retornando um `mfa_challenge_token`.
* ✅ **Segurança de Senha:** Hashing de senha forte (Bcrypt) com limite de 72 bytes.
* ✅ **Fluxos de Email (SendGrid):**
    * Verificação de Email para ativação de conta.
    * Recuperação de Senha ("esqueci minha senha").
* ✅ **Proteção de Login:**
    * Rate Limiting (SlowAPI).
    * Bloqueio de Conta (Account Lockout) após tentativas falhas.
    * Teste de integração para Lockout (`test_lockout.py`).
* ✅ **Autorização Agnóstica (Custom Claims):** Injeta `roles`, `permissions`, `store_id` ou qualquer outro dado customizado no JWT via `scope`.
* ✅ **API de Gerenciamento (Management):** Endpoints seguros (`/mgmt`) para gerenciar `custom_claims` de usuários via `X-API-Key`.
* ✅ **RBAC Interno:** Endpoints da própria API protegidos por roles (ex: "admin-only" para listar usuários).
* ✅ **Migrações de Banco de Dados:** Gerenciamento de schema seguro com Alembic.
* ✅ **Agnóstica de Banco de Dados:** Código compatível com PostgreSQL, SQLite, MySQL (requer driver async apropriado).
* ✅ **Async:** Totalmente assíncrono (FastAPI, SQLAlchemy 2.0, AsyncPG/AioSQLite).
* ✅ **Docker:** Suporte completo via `Dockerfile` e `docker-compose.yml`.
* ✅ **Login Social (Google OAuth2):**
    * Permite que os utilizadores façam login ou se registem usando a sua conta Google.

### Implementação Alternativa (Rust / Axum)

* **Reescrita de Performance:** Uma reescrita da API em Rust usando Axum, SQLx e Tokio.
* **Endpoints Implementados:** Inclui `/`, `/api/v1/users` (Registro), `/api/v1/auth/token` (Login) e `/api/v1/mgmt/users/{id}/claims`.
* **Migrações SQLx:** Usa `sqlx-cli` para migrações (separadas do Alembic).
* **Middleware de API Key:** Proteção da rota `/mgmt` com middleware (`X-API-Key`) em Rust, com comparação segura.

---

## 🚀 Começando (Python / FastAPI)

Esta é a implementação principal e mais completa.

### 📋 Pré-requisitos

* Python 3.10+
* Um servidor de banco de dados SQL rodando (ex: PostgreSQL)
* O driver `asyncpg` (para PostgreSQL)
* Uma conta SendGrid (API Key e Remetente Verificado)

### 1. Instalação

1.  Clone o repositório:
    ```bash
    git clone [https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git](https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git)
    cd SEU_REPOSITORIO
    ```
2.  Crie e ative um ambiente virtual:
    ```bash
    python -m venv venv
    source venv/bin/activate  # (Linux/macOS)
    .\venv\Scripts\activate   # (Windows)
    ```
3.  Instale as dependências:
    ```bash
    pip install -r requirements.txt
    pip install -r requirements-dev.txt
    ```

### 2. Configuração

1.  Crie um banco de dados (ex: `auth_db`).
2.  Crie um arquivo `.env` na raiz do projeto (copie de `.env.example` se existir) e preencha as variáveis:

    ```ini
    # --- Banco de Dados ---
    # AJUSTE com o driver async correto e suas credenciais
    DATABASE_URL="postgresql+asyncpg://USUARIO:SENHA@localhost:5432/auth_db"
    # Exemplo SQLite: DATABASE_URL="sqlite+aiosqlite:///./auth.db"

    # --- Chaves Secretas (use 'openssl rand -hex 32' para gerar) ---
    SECRET_KEY="SUA_CHAVE_SECRETA_FORTE_AQUI"
    REFRESH_SECRET_KEY="UMA_CHAVE_SECRETA_DIFERENTE_E_FORTE_AQUI"
    ALGORITHM="HS256"

    # --- Chave da API de Gerenciamento (use 'openssl rand -hex 64') ---
    INTERNAL_API_KEY="sk_live_UMA_CHAVE_SECRETA_MUITO_FORTE_PARA_SISTEMAS"

    # --- Configurações de Email (SendGrid) ---
    SENDGRID_API_KEY="SG.SUA_CHAVE_API_SENDGRID_AQUI"
    EMAIL_FROM="seu_email_verificado@sendgrid.com"
    EMAIL_FROM_NAME="Auth API"

    # --- URLs do SEU Frontend ---
    VERIFICATION_URL_BASE="http://localhost:3000/verify-email"
    RESET_PASSWORD_URL_BASE="http://localhost:3000/reset-password"

    # --- Configurações de Segurança (Account Lockout) ---
    LOGIN_MAX_FAILED_ATTEMPTS=5
    LOGIN_LOCKOUT_MINUTES=15

    # --- Configurações OIDC JWT Claims ---
    JWT_ISSUER="http://localhost:8001" # URL base da sua API Auth
    JWT_AUDIENCE="vrsales-api" # ID da sua API principal (ex: VRSales)
    ```

### 3. Migrar o Banco de Dados (Alembic)

Este projeto usa Alembic para gerenciar o schema do banco de dados de forma segura.

Para criar todas as tabelas pela primeira vez ou aplicar novas alterações de schema (como as de MFA), rode:

```bash
alembic upgrade head
```

Isso criará/atualizará as tabelas users (com campos otp_secret, is_mfa_enabled), refresh_tokens e alembic_version no banco.

### 4. Rodar o Servidor
Use o Uvicorn para rodar a aplicação:

```Bash
# O --reload monitora mudanças nos arquivos (ótimo para dev)
uvicorn main:app --host 0.0.0.0 --port 8001 --reload 
```
A API estará disponível em http://localhost:8001 🚀. A documentação interativa (Swagger UI) estará em http://localhost:8001/docs.

### 🐳 Rodando com Docker (Recomendado)
Para uma experiência mais isolada e consistente com a implementação Python.

1. Configure o .env: Preencha o arquivo .env como na seção "Configuração" acima. A única diferença é que o DATABASE_URL deve apontar para o serviço do banco de dados do Docker:

```DATABASE_URL="postgresql+asyncpg://user:password@db:5432/auth_db"```
_(Estes valores vêm do docker-compose.yml)_

2. Build e Run: Suba os serviços (API e banco de dados) em background:

```Bash
docker-compose up --build -d
```

3. Aplicar Migrações: Execute as migrações do Alembic dentro do container da aplicação:

```Bash
docker-compose exec app alembic upgrade head
```
A API (Python) estará disponível em http://localhost:8001.

# 🚀 Começando (Rust / Axum)
Esta é uma implementação alternativa focada em performance, localizada na pasta ```/rust.```

### 1. Instalação (Rust)
1. Navegue até o diretório Rust:

```Bash
cd rust
```

2. Instale o sqlx-cli (se ainda não o tiver):

```Bash
cargo install sqlx-cli --features rustls,postgres
```
### 2. Configuração (Rust)
Crie um arquivo ```.env``` dentro da pasta ```rust``` e adicione:

```Ini, TOML
# --- Database ---
DATABASE_URL="sqlite:auth.db" # ou "postgresql://user:pass@host/db"

# --- Secret Keys (generate with 'openssl rand -hex 32') ---
SECRET_KEY="YOUR_STRONG_SECRET_KEY"
REFRESH_SECRET_KEY="A_DIFFERENT_STRONG_SECRET_KEY"

# --- Management API Key (generate with 'openssl rand -hex 64') ---
INTERNAL_API_KEY="sk_live_A_VERY_STRONG_SECRET_KEY_FOR_SYSTEMS"

# --- OIDC JWT Claims Settings ---
JWT_ISSUER="http://localhost:8001"
JWT_AUDIENCE="yourapp-api"

# --- Server Settings ---
HOST="127.0.0.1"
PORT="8001"
```

### 3. Migrar o Banco de Dados (SQLx)
Na pasta ```rust```, rode:

```Bash
sqlx migrate run
```
Isso executará os scripts SQL na pasta ```rust/migrations.```

*** 4. Rodar o Servidor (Rust)

```Bash
cargo run
```
O servidor Rust estará disponível em ```http://localhost:8001.```

# 🛠️ Fluxo de Integração (Tutorial)
Este é o guia passo-a-passo de como um desenvolvedor deve integrar esta Auth API (Python) em seu sistema (ex: um E-commerce).

### Passo 1: ✍️ Registrar o Usuário (Backend Cliente -> API Auth)
O usuário se registra no seu sistema. O backend do seu sistema faz uma chamada para a Auth API.

`POST /api/v1/users/`

```Bash
curl -X 'POST' 'http://localhost:8001/api/v1/users/' \
-H 'Content-Type: application/json' \
-d '{
    "email": "novo_usuario@meusistema.com",
    "password": "Password123!",
    "full_name": "Nome Completo"
}'
```
Resultado: O usuário é criado com `is_active: false.` Um email de verificação é enviado em background.

### Passo 2: 📧 Ativar o Usuário (Usuário -> Frontend -> API Auth)
O usuário clica no link em seu email. O link aponta para o seu frontend `(VERIFICATION_URL_BASE)`, que extrai o token da URL e chama a API Auth:

`GET /api/v1/auth/verify-email/{token}`

Resultado: O usuário é atualizado para `is_active: true`, `is_verified: true.`

### Passo 3: 🔑 Definir Roles e Claims (Backend Cliente -> API Auth)
O backend do seu sistema (E-commerce) decide quais permissões (roles, etc.) esse usuário tem. Ele usa a API de Gerenciamento (/mgmt), autenticando-se com a INTERNAL_API_KEY.

`PATCH /api/v1/mgmt/users/{id_ou_email}/claims`

```Bash
curl -X 'PATCH' \
'http://localhost:8001/api/v1/mgmt/users/novo_usuario@meusistema.com/claims' \
-H 'X-API-Key: sk_live_UMA_CHAVE_SECRETA_MUITO_FORTE...' \
-H 'Content-Type: application/json' \
-d '{
    "roles": ["user", "beta_tester"],
    "permissions": ["read:products", "write:cart"],
    "ecommerce_user_id": 4567
}'
```
Resultado: A API Auth armazena este JSON no campo custom_claims do usuário.

### Passo 4: 🎟️ Login com Scopes (Frontend -> API Auth)
Quando o usuário faz login, o frontend chama a API Auth, pedindo os `scopes` (claims customizados) que sua aplicação precisa.

`POST /api/v1/auth/token`

```Bash
# Frontend envia como application/x-www-form-urlencoded
curl -X 'POST' 'http://localhost:8001/api/v1/auth/token' \
-H 'Content-Type: application/x-www-form-urlencoded' \
-d 'username=novo_usuario@meusistema.com&password=Password123!&scope=roles+permissions+ecommerce_user_id'
```

### Passo 5: 🛡️ Fluxo de Login (Interpretação da Resposta)
Caso A: Login normal (Sem MFA)
A API Auth retorna `HTTP 200` com os tokens. O payload do `access_token` (decodificado) será:

```JSON

{
  "iss": "http://localhost:8001",
  "aud": "vrsales-api",
  "sub": "123",
  "exp": 1678886400,
  "email": "novo_usuario@meusistema.com",
  "amr": ["pwd"], // Authentication Method: Password
  "roles": ["user", "beta_tester"], // Veio do custom_claims via scope
  "permissions": ["read:products", "write:cart"], // Veio do custom_claims
  "ecommerce_user_id": 4567 // Veio do custom_claims
}
```

### Caso B: Login com MFA Habilitado
A API Auth retorna `HTTP 200` com um challenge token:

```JSON
{
  "detail": "MFA verification required",
  "mfa_challenge_token": "eyJhbGciOiJIUzI1NiIs... (token de 5 min)"
}
```
O frontend deve então exibir a tela "Insira seu código de 6 dígitos" e fazer uma segunda chamada:

`POST /api/v1/auth/mfa/verify`

```Bash
curl -X 'POST' 'http://localhost:8001/api/v1/auth/mfa/verify' \
-H 'Content-Type: application/json' \
-d '{
    "mfa_challenge_token": "eyJhbGciOiJIUzI1NiIs... (token de 5 min)",
    "otp_code": "123456"
}'
```
Se o código estiver correto, a API retorna `HTTP 200` com os tokens. O payload do `access_token` agora refletirá que o MFA foi validado:

```JSON

{
  "iss": "http://localhost:8001",
  "aud": "vrsales-api",
  "sub": "123",
  "exp": 1678886400,
  "email": "novo_usuario@meusistema.com",
  "amr": ["pwd", "mfa"], // Authentication Methods: Password E MFA
  "roles": ["user", "beta_tester"],
  "permissions": ["read:products", "write:cart"],
  "ecommerce_user_id": 4567
}
```

### Passo 6: 🛡️ Usar o JWT (Frontend -> Backend Cliente)
O frontend envia o `access_token` final para o backend do seu E-commerce (ex: `GET /api/products`) no header `Authorization: <token>`.

O backend do seu E-commerce (VRSales) só precisa:

1. Validar a assinatura, expiração, `iss` (issuer) e `aud` (audience) do JWT.

2. Opcional (Recomendado): Verificar o claim `amr`. Se sua rota (`/admin/delete_product`) exige alta segurança, você pode rejeitar tokens que não contenham `"mfa"` no array `amr`.

3. Olhar os claims (`token_data["roles"]`, `token_data["ecommerce_user_id"]`) e aplicar sua própria lógica de autorização.

Seu backend E-commerce nunca mais precisará consultar o banco de dados da API Auth para saber quem é o usuário ou o que ele pode fazer a cada requisição.

### Passo 7: 🔐 Autenticação Multifator (MFA/2FA)

Esta API suporta MFA baseado em Tempo (TOTP) usando aplicações autenticadoras como Google Authenticator ou Authy.

**Fluxo de Habilitação:**

1.  **Iniciar:** O utilizador autenticado chama `POST /api/v1/auth/mfa/enable`.
    * **Ação:** A API gera um segredo OTP, guarda-o temporariamente, e retorna uma `otp_uri` e um `qr_code_base64`.
    * **Frontend:** Mostra o QR Code ou a URI para o utilizador escanear na sua app autenticadora.

2.  **Confirmar:** O utilizador insere o código de 6 dígitos da app e chama `POST /api/v1/auth/mfa/confirm` com o `otp_code`.
    * **Ação:** A API verifica o código OTP contra o segredo pendente. Se válido, marca `is_mfa_enabled = True`, gera 10 códigos de recuperação de uso único, guarda os seus hashes, e retorna o utilizador atualizado juntamente com os **códigos de recuperação em texto simples**.
    * **Frontend:** Mostra os códigos de recuperação ao utilizador **APENAS NESTA ALTURA**, instruindo-o a guardá-los num local seguro.

**Fluxo de Login com MFA:**

1.  **Senha:** O utilizador envia e-mail e senha para `POST /api/v1/auth/token`.
2.  **Desafio:** Se a senha estiver correta e MFA estiver ativo, a API retorna `200 OK` com um `mfa_challenge_token` temporário.
3.  **Verificação (Opção 1 - OTP):** O utilizador insere o código da app autenticadora e chama `POST /api/v1/auth/mfa/verify` com o `mfa_challenge_token` e o `otp_code`.
4.  **Verificação (Opção 2 - Recuperação):** Se o utilizador perdeu o acesso à app, ele insere um dos seus códigos de recuperação guardados e chama `POST /api/v1/auth/mfa/verify-recovery` com o `mfa_challenge_token` e o `recovery_code`.
5.  **Sucesso:** Se a verificação (OTP ou recuperação) for válida, a API retorna os tokens JWT finais (`access_token`, `refresh_token`). O código de recuperação utilizado é marcado como inválido.

**Fluxo de Desabilitação:**

1.  O utilizador autenticado chama `POST /api/v1/auth/mfa/disable` enviando um `otp_code` válido atual.
2.  A API verifica o código, marca `is_mfa_enabled = False`, apaga o `otp_secret` e **apaga todos os códigos de recuperação associados**.

---

### Passo 8: 🌐 Login Social (Google OAuth2)

Permite que os utilizadores façam login ou se registem usando a sua conta Google.

**Configuração Prévia:**

1.  Registe a sua aplicação na Google Cloud Console para obter um `Client ID` e `Client Secret`.
2.  Adicione o **URI de redirecionamento do seu frontend** (ex: `http://localhost:3000/google-callback`) aos "Authorized redirect URIs" na Google Cloud Console.
3.  Adicione `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, e `GOOGLE_REDIRECT_URI_FRONTEND` ao seu ficheiro `.env`.
4.  Certifique-se de que a coluna `hashed_password` na tabela `users` permite valores `NULL` (necessário executar a migração Alembic correspondente).

**Fluxo de Autenticação (Produção):**

1.  **Frontend -> API:** Chama `GET /api/v1/auth/google/login-url`.
    * **Resposta da API:** `{ "url": "https://accounts.google.com/o/oauth2/..." }` (o URL é construído com o `GOOGLE_REDIRECT_URI_FRONTEND`).
2.  **Frontend -> Utilizador:** Redireciona o browser do utilizador para o URL recebido.
3.  **Utilizador -> Google:** Faz login na Google e autoriza a sua aplicação.
4.  **Google -> Frontend:** Redireciona o browser do utilizador de volta para o `GOOGLE_REDIRECT_URI_FRONTEND` com um parâmetro `code` (ex: `http://localhost:3000/google-callback?code=ABC123XYZ...`).
5.  **Frontend -> API:** Extrai o `code` do URL e chama `POST /api/v1/auth/google/callback` com o corpo JSON `{"code": "ABC123XYZ..."}`.
6.  **API -> Google:** A API troca o `code` pelo perfil do utilizador Google (usando o `CLIENT_SECRET`).
7.  **API (Interno):** Procura o utilizador pelo e-mail na base de dados. Se não existir, cria um novo utilizador (já ativo e verificado, sem senha).
8.  **API -> Frontend:** Gera e retorna os tokens JWT (`access_token`, `refresh_token`) da *sua própria* API.
9.  **Frontend:** Guarda os tokens e considera o utilizador autenticado.

# 📚 Referência da API (Python/FastAPI)
A API é dividida em três seções principais. Para detalhes completos dos endpoints e schemas, veja a documentação interativa em `/docs`.

### 1. 🔑 Authentication (`/api/v1/auth`)
`POST /token`: Login (Pode retornar `Token` ou `MFARequiredResponse)`.

`POST /mfa/verify`: Verifica o código OTP após o login (retorna `Token`).

`POST /mfa/enable`: Inicia a habilitação do MFA (retorna `MFAEnableResponse` com QR Code).

`POST /mfa/confirm`: Confirma e ativa o MFA com o primeiro código.

`POST /mfa/disable`: Desativa o MFA (requer um código OTP válido).

`POST /refresh`: Obter um novo `access_token` (o novo token terá `amr: ["pwd"])`.

`POST /logout`: Revogar um `refresh_token`.

`GET /verify-email/{token}`: Ativar uma conta.

`POST /forgot-password`: Iniciar o fluxo de reset de senha.

`POST /reset-password`: Definir uma nova senha com um token.

`GET /me`: Obter os dados do usuário logado (requer token).

### 2. 👤 User Management (`/api/v1/users`)
`POST /`: Registrar um novo usuário (público).

`GET /`: Listar usuários (Protegido, requer role 'admin').

`GET /{user_id}`: Buscar um usuário por ID (Protegido, requer role 'admin').

`PUT /me`: Atualizar os dados do próprio usuário logado.

### 3. ⚙️ Internal Management (`/api/v1/mgmt`)
Proteção: Requer o `INTERNAL_API_KEY` no header `X-API-Key`.

`PATCH /users/{id_ou_email}/claims`: Mescla (Atualiza) os `custom_claims` de um usuário.

# 📜 Licença
Este projeto está licenciado sob a Licença MIT. Veja o arquivo [`LICENSE`](https://github.com/Verax-System/Verax-AuthAPI/blob/master/LICENSE) para mais detalhes.
