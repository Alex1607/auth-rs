use mongodb::bson::Uuid;
use rocket::serde;
use std::env::VarError;
use thiserror::Error;

use crate::models::http_response::HttpResponse;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid UUID: {0}")]
    InvalidUuid(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("MongoDB error: {0}")]
    MongoError(#[from] mongodb::error::Error),

    #[error("Rocket MongoDB error: {0}")]
    RocketMongoError(#[from] rocket_db_pools::mongodb::error::Error),

    #[error("User not found: {0}")]
    UserNotFound(Uuid),

    #[error("Role not found: {0}")]
    RoleNotFound(Uuid),

    #[error("Missing permissions")]
    MissingPermissions,

    #[error("Cannot modify system user")]
    SystemUserModification,

    #[error("Password hashing error: {0}")]
    PasswordHashingError(String),

    #[error("Only system admin can assign admin role")]
    AdminRoleAssignment,

    #[error("No updates applied")]
    NoUpdatesApplied,

    #[error("Internal server error: {0}")]
    InternalServerError(String),

    #[error("Environment variable error: {0}")]
    EnvVarError(#[from] VarError),

    #[error("Authentication error: {0}")]
    AuthenticationError(String),

    #[error("Invalid token")]
    InvalidToken,

    #[error("Token expired")]
    TokenExpired,

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("MFA required")]
    MfaRequired,

    #[error("Invalid MFA code")]
    InvalidMfaCode,

    #[error("User is disabled")]
    UserDisabled,

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("HTTP response error: {0}")]
    HttpResponseError(String),
}

// Implement From<HttpResponse<T>> for AppError
impl<T> From<HttpResponse<T>> for AppError
where
    T: serde::Serialize,
{
    fn from(response: HttpResponse<T>) -> Self {
        AppError::HttpResponseError(format!(
            "HTTP error {}: {}",
            response.status, response.message
        ))
    }
}

impl<T> From<AppError> for HttpResponse<T> {
    fn from(error: AppError) -> Self {
        match error {
            AppError::InvalidUuid(msg) => HttpResponse {
                status: 400,
                message: format!("Invalid UUID: {}", msg),
                data: None,
            },
            AppError::DatabaseError(err) => HttpResponse {
                status: 500,
                message: format!("Database error: {}", err),
                data: None,
            },
            AppError::MongoError(err) => HttpResponse {
                status: 500,
                message: format!("MongoDB error: {}", err),
                data: None,
            },
            AppError::RocketMongoError(err) => HttpResponse {
                status: 500,
                message: format!("MongoDB error: {}", err),
                data: None,
            },
            AppError::UserNotFound(id) => HttpResponse {
                status: 404,
                message: format!("User with ID {} not found", id),
                data: None,
            },
            AppError::RoleNotFound(id) => HttpResponse {
                status: 400,
                message: format!("Role with ID {} does not exist", id),
                data: None,
            },
            AppError::MissingPermissions => HttpResponse {
                status: 403,
                message: "Missing permissions!".to_string(),
                data: None,
            },
            AppError::SystemUserModification => HttpResponse {
                status: 403,
                message: "Cannot modify system user".to_string(),
                data: None,
            },
            AppError::PasswordHashingError(msg) => HttpResponse {
                status: 500,
                message: format!("Failed to hash password: {}", msg),
                data: None,
            },
            AppError::AdminRoleAssignment => HttpResponse {
                status: 403,
                message: "Only system admin can assign admin role".to_string(),
                data: None,
            },
            AppError::NoUpdatesApplied => HttpResponse {
                status: 200,
                message: "No updates applied.".to_string(),
                data: None,
            },
            AppError::InternalServerError(msg) => HttpResponse {
                status: 500,
                message: format!("Internal server error: {}", msg),
                data: None,
            },
            AppError::EnvVarError(err) => HttpResponse {
                status: 500,
                message: format!("Environment variable error: {}", err),
                data: None,
            },
            AppError::AuthenticationError(msg) => HttpResponse {
                status: 401,
                message: format!("Authentication error: {}", msg),
                data: None,
            },
            AppError::InvalidToken => HttpResponse {
                status: 401,
                message: "Invalid token".to_string(),
                data: None,
            },
            AppError::TokenExpired => HttpResponse {
                status: 401,
                message: "Token expired".to_string(),
                data: None,
            },
            AppError::InvalidCredentials => HttpResponse {
                status: 401,
                message: "Invalid credentials".to_string(),
                data: None,
            },
            AppError::MfaRequired => HttpResponse {
                status: 401,
                message: "MFA required".to_string(),
                data: None,
            },
            AppError::InvalidMfaCode => HttpResponse {
                status: 401,
                message: "Invalid MFA code".to_string(),
                data: None,
            },
            AppError::UserDisabled => HttpResponse {
                status: 403,
                message: "User is disabled".to_string(),
                data: None,
            },
            AppError::ValidationError(msg) => HttpResponse {
                status: 400,
                message: format!("Validation error: {}", msg),
                data: None,
            },
            AppError::HttpResponseError(msg) => HttpResponse {
                status: 500,
                message: msg,
                data: None,
            },
        }
    }
}

// Result type alias for application
pub type AppResult<T> = Result<T, AppError>;
