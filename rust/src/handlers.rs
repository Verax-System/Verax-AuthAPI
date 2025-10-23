use axum::{Json, http::StatusCode, Extension};
use serde::{Deserialize, Serialize};
use crate::models::User;
use crate::auth::{hash_password, verify_password, create_access_token, create_refresh_token};
use sqlx::SqlitePool;

#[derive(Deserialize)]
pub struct RegisterUser {
    pub email: String,
    pub password: String,
    pub full_name: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: i32,
    pub email: String,
    pub full_name: Option<String>,
}

pub async fn register(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<RegisterUser>,
) -> (StatusCode, Json<UserResponse>) {
    let hashed_password = hash_password(&payload.password).unwrap();

    let result = sqlx::query!(
        "INSERT INTO users (email, password, full_name) VALUES ($1, $2, $3)",
        payload.email,
        hashed_password,
        payload.full_name
    )
    .execute(&pool)
    .await;

    match result {
        Ok(query_result) => {
            let last_insert_id = query_result.last_insert_rowid();
            let new_user = sqlx::query_as_unchecked!(
                User,
                "SELECT id, email, password, full_name, is_active, is_verified, custom_claims, created_at, updated_at FROM users WHERE id = $1",
                last_insert_id
            )
            .fetch_one(&pool)
            .await;

            match new_user {
                Ok(user) => {
                    let user_response = UserResponse {
                        id: user.id,
                        email: user.email,
                        full_name: user.full_name,
                    };
                    (StatusCode::CREATED, Json(user_response))
                }
                Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(UserResponse {
                    id: -1,
                    email: "".to_string(),
                    full_name: None,
                })),
            }
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, Json(UserResponse {
            id: -1,
            email: "".to_string(),
            full_name: None,
        })),
    }
}

#[derive(Deserialize)]
pub struct UpdateClaims {
    pub custom_claims: serde_json::Value,
}

pub async fn update_claims(Json(payload): Json<UpdateClaims>) -> StatusCode {
    // Lógica para atualizar claims será implementada aqui
    println!("Atualizando claims: {:?}", payload.custom_claims);
    StatusCode::OK
}

#[derive(Deserialize)]
pub struct LoginUser {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
}

pub async fn login(
    Extension(pool): Extension<SqlitePool>,
    Json(payload): Json<LoginUser>,
) -> (StatusCode, Json<TokenResponse>) {
    let user = sqlx::query_as_unchecked!(
        User,
        "SELECT id, email, password, full_name, is_active, is_verified, custom_claims, created_at, updated_at FROM users WHERE email = $1",
        payload.email
    )
    .fetch_one(&pool)
    .await;

    match user {
        Ok(user) => {
            if verify_password(&payload.password, &user.password).unwrap() {
                let access_token = create_access_token(&user.id.to_string()).unwrap();
                let refresh_token = create_refresh_token(&user.id.to_string()).unwrap();

                (StatusCode::OK, Json(TokenResponse {
                    access_token,
                    refresh_token,
                }))
            } else {
                (StatusCode::UNAUTHORIZED, Json(TokenResponse {
                    access_token: "".to_string(),
                    refresh_token: "".to_string(),
                }))
            }
        }
        Err(_) => (StatusCode::UNAUTHORIZED, Json(TokenResponse {
            access_token: "".to_string(),
            refresh_token: "".to_string(),
        })),
    }
}
