use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

#[derive(Debug)]
pub enum AppError {
    Internal(String),
    BadRequest(String),
    #[allow(dead_code)]
    Unauthorized(String),
    #[allow(dead_code)]
    NotFound(String),
    Database(sqlx::Error),
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppError::Internal(msg) => write!(f, "Internal error: {msg}"),
            AppError::BadRequest(msg) => write!(f, "Bad request: {msg}"),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            AppError::NotFound(msg) => write!(f, "Not found: {msg}"),
            AppError::Database(e) => write!(f, "Database error: {e}"),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {msg}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Unauthorized(_) => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            AppError::NotFound(_) => (StatusCode::NOT_FOUND, "Not found".to_string()),
            AppError::Database(e) => {
                tracing::error!("Database error: {e}");
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        (status, Html(format!("<h1>{}</h1><p>{}</p>", status, message))).into_response()
    }
}

impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        AppError::Database(e)
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        AppError::Internal(format!("JWT error: {e}"))
    }
}

impl From<tera::Error> for AppError {
    fn from(e: tera::Error) -> Self {
        AppError::Internal(format!("Template error: {e}"))
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(e: argon2::password_hash::Error) -> Self {
        AppError::Internal(format!("Password hash error: {e}"))
    }
}
