use auth_api_rust::app;
use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use sqlx::{Pool, Sqlite};
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;

async fn spawn_app() -> (SocketAddr, Pool<Sqlite>) {
    dotenvy::dotenv().ok();
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = Pool::<Sqlite>::connect(&database_url)
        .await
        .expect("Failed to create pool.");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind random port");
    let addr = listener.local_addr().unwrap();

    let app_pool = pool.clone();
    tokio::spawn(async move {
        axum::serve(listener, app(app_pool)).await.unwrap();
    });

    (addr, pool)
}

#[tokio::test]
async fn test_hello_world() {
    let (addr, _pool) = spawn_app().await;
    let client = Client::builder(TokioExecutor::new()).build_http();

    let request = hyper::Request::builder()
        .uri(format!("http://{}", addr))
        .body(Empty::<Bytes>::new())
        .unwrap();

    let response = client.request(request).await.unwrap();

    assert_eq!(response.status(), hyper::StatusCode::OK);

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert_eq!(body_str, "Olá, Mundo!");
}
