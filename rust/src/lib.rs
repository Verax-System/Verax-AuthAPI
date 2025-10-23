use axum::{
    routing::{get, post, patch},
    Router, Extension,
};
use std::net::SocketAddr;
use tokio;
use dotenvy::dotenv;
use std::env;
use sqlx::SqlitePool;

pub mod models;
pub mod auth;
pub mod handlers;
pub mod middleware;

pub fn app(pool: SqlitePool) -> Router {
    let mgmt_routes = Router::new()
        .route("/users/{id}/claims", patch(handlers::update_claims))
        .route_layer(axum::middleware::from_fn(middleware::auth_middleware));

    Router::new()
        .route("/", get(hello))
        .route("/api/v1/users", post(handlers::register))
        .route("/api/v1/auth/token", post(handlers::login))
        .nest("/api/v1/mgmt", mgmt_routes)
        .layer(Extension(pool))
}

pub async fn run() {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = SqlitePool::connect(&database_url)
        .await
        .expect("Failed to create pool.");

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8001".to_string());
    let addr: SocketAddr = format!("{}:{}", host, port)
        .parse()
        .expect("Endereço e porta inválidos");

    println!("Servidor rodando em http://{}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app(pool)).await.unwrap();
}


async fn hello() -> &'static str {
    "Olá, Mundo!"
}
