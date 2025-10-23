# AuthAPI in Rust

This is a complete rewrite of the original AuthAPI in Rust, using Axum, SQLx, and other modern Rust libraries.

## 🚀 Getting Started

### 📋 Prerequisites

- Rust 1.60+
- A running SQL database server (e.g., PostgreSQL, MySQL, or SQLite)
- `sqlx-cli` for database migrations: `cargo install sqlx-cli --features rustls,postgres`

### 1. Installation

Clone the repository:

```bash
git clone https://github.com/SEU_USUARIO/SEU_REPOSITORIO.git
cd SEU_REPOSITORIO/rust
```

### 2. Configuration

Create a `.env` file in the `rust` directory and add/adjust the following variables:

```ini
# --- Database ---
DATABASE_URL="sqlite:auth.db" # or "postgresql://user:pass@host/db"

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

### 3. Database Migrations

This project uses `sqlx-cli` to manage database schema migrations.

To create all tables for the first time or apply new schema changes, run:

```bash
sqlx migrate run
```

This will create/update the tables `users`, `refresh_tokens`, and `_sqlx_migrations` in the database configured in `.env`.

### 4. Running the Server

Use `cargo` to run the application:

```bash
cargo run
```

The API will be available at `http://localhost:8001`.
