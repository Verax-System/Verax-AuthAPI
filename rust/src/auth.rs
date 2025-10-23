use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use std::env;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub exp: usize,
    pub iat: usize,
    pub iss: String,
    pub aud: String,
}

// Função para criar o hash de uma senha
pub fn hash_password(password: &str) -> Result<String, bcrypt::BcryptError> {
    hash(password, DEFAULT_COST)
}

// Função para verificar se a senha corresponde ao hash
pub fn verify_password(password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
    verify(password, hash)
}

// Função para criar um novo token de acesso
pub fn create_access_token(user_id: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::minutes(15))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration as usize,
        iat: Utc::now().timestamp() as usize,
        iss: env::var("JWT_ISSUER").unwrap_or_else(|_| "AuthAPI".to_string()),
        aud: env::var("JWT_AUDIENCE").unwrap_or_else(|_| "user".to_string()),
    };

    let secret = env::var("SECRET_KEY").expect("SECRET_KEY must be set");
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
}

// Função para criar um novo token de atualização
pub fn create_refresh_token(user_id: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now()
        .checked_add_signed(Duration::days(7))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id.to_owned(),
        exp: expiration as usize,
        iat: Utc::now().timestamp() as usize,
        iss: env::var("JWT_ISSUER").unwrap_or_else(|_| "AuthAPI".to_string()),
        aud: env::var("JWT_AUDIENCE").unwrap_or_else(|_| "user".to_string()),
    };

    let secret = env::var("REFRESH_SECRET_KEY").expect("REFRESH_SECRET_KEY must be set");
    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_ref()))
}

// Função para verificar um token
pub fn verify_token(token: &str, is_refresh: bool) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = if is_refresh {
        env::var("REFRESH_SECRET_KEY").expect("REFRESH_SECRET_KEY must be set")
    } else {
        env::var("SECRET_KEY").expect("SECRET_KEY must be set")
    };

    let mut validation = Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.set_audience(&[env::var("JWT_AUDIENCE").unwrap_or_else(|_| "user".to_string())]);
    validation.set_issuer(&[env::var("JWT_ISSUER").unwrap_or_else(|_| "AuthAPI".to_string())]);

    decode::<Claims>(token, &DecodingKey::from_secret(secret.as_ref()), &validation)
        .map(|data| data.claims)
}
