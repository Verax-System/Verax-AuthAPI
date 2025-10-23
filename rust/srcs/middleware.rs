use axum::{
    body::Body,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use std::env;
use subtle::ConstantTimeEq;

pub async fn auth_middleware(req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let api_key = env::var("INTERNAL_API_KEY").expect("INTERNAL_API_KEY must be set");

    let auth_header = req.headers().get("X-API-Key");

    if let Some(header_value) = auth_header {
        let provided_key = header_value.as_bytes();
        if api_key.as_bytes().ct_eq(provided_key).unwrap_u8() == 1 {
            return Ok(next.run(req).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}
