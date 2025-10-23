use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::env;

pub async fn auth_middleware(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let api_key = env::var("INTERNAL_API_KEY").expect("INTERNAL_API_KEY must be set");

    let auth_header = req.headers().get("X-API-Key");

    match auth_header {
        Some(header) if header.to_str().unwrap_or("") == api_key => {
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
