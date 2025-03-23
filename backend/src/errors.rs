use mongodb::bson::Uuid;
use rocket::serde;
use std::env::VarError;
use thiserror::Error;

use crate::models::http_response::HttpResponse;
use crate::models::oauth_application::OAuthApplicationError;
use crate::models::passkey_error::PasskeyError;

use crate::models::role::RoleError;
use crate::models::user_error::UserError;

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

    #[error("Password hashing error")]
    PasswordHashingError,

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

    #[error("User is disabled")]
    UserDisabled,

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Invalid or missing fields: {0}")]
    InvalidOrMissingFields(String),

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
            AppError::PasswordHashingError => HttpResponse {
                status: 500,
                message: "Error during password hashing".to_string(),
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

            AppError::InvalidOrMissingFields(msg) => HttpResponse {
                status: 400,
                message: format!("Invalid or missing fields: {}", msg),
                data: None,
            },
        }
    }
}

// Result type alias for application
pub type AppResult<T> = Result<T, AppError>;

// Add this new error type for API-specific errors
#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Internal server error: {0}")]
    InternalError(String),

    #[error("App error: {0}")]
    AppError(#[from] AppError),
}

// Implement conversion from ApiError to HttpResponse
impl<T> From<ApiError> for HttpResponse<T> {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::NotFound(msg) => HttpResponse::not_found(&msg),
            ApiError::BadRequest(msg) => HttpResponse::bad_request(&msg),
            ApiError::Unauthorized(msg) => HttpResponse::unauthorized(&msg),
            ApiError::Forbidden(msg) => HttpResponse::forbidden(&msg),
            ApiError::InternalError(msg) => HttpResponse::internal_error(&msg),
            ApiError::AppError(err) => HttpResponse::from(err),
        }
    }
}

// Add a type alias for API results
pub type ApiResult<T> = Result<T, ApiError>;

// Implement conversion from UserError to AppError
impl From<UserError> for AppError {
    fn from(error: UserError) -> Self {
        match error {
            UserError::NotFound(id) => AppError::UserNotFound(id),
            UserError::EmailAlreadyExists(email) => {
                AppError::ValidationError(format!("User with email {} already exists", email))
            }
            UserError::InvalidUuid(msg) => AppError::InvalidUuid(msg),
            UserError::MissingPermissions => AppError::MissingPermissions,
            UserError::SystemUserModification => AppError::SystemUserModification,
            UserError::PasswordHashingError => AppError::PasswordHashingError,
            UserError::AdminRoleAssignment => AppError::AdminRoleAssignment,
            UserError::RoleNotFound(id) => AppError::RoleNotFound(id),
            UserError::UserDisabled => AppError::UserDisabled,
            UserError::NoUpdatesApplied => AppError::NoUpdatesApplied,
            UserError::DatabaseError(msg) => AppError::DatabaseError(msg),
            UserError::InternalServerError(msg) => AppError::InternalServerError(msg),
            UserError::InvalidEmail => {
                AppError::InvalidOrMissingFields("Invalid email".to_string())
            }
            UserError::FirstNameRequired => {
                AppError::InvalidOrMissingFields("First name required".to_string())
            }
            UserError::PasswordToShort => {
                AppError::InvalidOrMissingFields("Password too short".to_string())
            },
            UserError::PasskeyNotFound(id) => {
                AppError::ValidationError(format!("Passkey with ID {} not found", id))
            },
            UserError::PasswordNotSet => {
                AppError::ValidationError("Password not set for this user".to_string())
            }
        }
    }
}

impl From<OAuthApplicationError> for AppError {
    fn from(error: OAuthApplicationError) -> Self {
        match error {
            OAuthApplicationError::NotFound(id) => {
                AppError::InternalServerError(format!("OAuth Application with ID {} not found", id))
            }
            OAuthApplicationError::InvalidData(msg) => {
                AppError::ValidationError(format!("Invalid OAuth Application data: {}", msg))
            }
            OAuthApplicationError::DatabaseError(msg) => AppError::DatabaseError(msg),
            OAuthApplicationError::InternalServerError(msg) => AppError::InternalServerError(msg),
        }
    }
}

impl From<RoleError> for AppError {
    fn from(error: RoleError) -> Self {
        match error {
            RoleError::NotFound(id) => AppError::RoleNotFound(id),
            RoleError::NameNotFound(name) => {
                AppError::ValidationError(format!("Role with name {} not found", name))
            }
            RoleError::NameAlreadyExists(name) => {
                AppError::ValidationError(format!("Role with name {} already exists", name))
            }
            RoleError::SystemRoleModification => AppError::SystemUserModification,
            RoleError::DatabaseError(msg) => AppError::DatabaseError(msg),
            RoleError::InternalServerError(msg) => AppError::InternalServerError(msg),
        }
    }
}

impl From<PasskeyError> for AppError {
    fn from(error: PasskeyError) -> Self {
        match error {
            PasskeyError::ChallengeNotFound =>
                AppError::ValidationError("Challenge not found or expired".to_string()),
            PasskeyError::InvalidChallenge =>
                AppError::ValidationError("Invalid challenge".to_string()),
            PasskeyError::ChallengeExpired =>
                AppError::ValidationError("Challenge expired".to_string()),
            PasskeyError::InvalidCredentialId =>
                AppError::ValidationError("Invalid credential ID".to_string()),
            PasskeyError::InvalidPublicKey =>
                AppError::ValidationError("Invalid public key format".to_string()),
            PasskeyError::CredentialNotFound =>
                AppError::ValidationError("Credential ID not found for user".to_string()),
            PasskeyError::PasskeyAlreadyRegistered =>
                AppError::ValidationError("Passkey already registered for this user".to_string()),
            PasskeyError::ReplayAttack =>
                AppError::ValidationError("Possible replay attack detected".to_string()),
            PasskeyError::UserNotFound =>
                AppError::ValidationError("No user associated with this challenge".to_string()),
            PasskeyError::DatabaseError(msg) =>
                AppError::DatabaseError(msg),
            PasskeyError::UpdateError(msg) =>
                AppError::InternalServerError(format!("Failed to update passkey: {}", msg)),
            PasskeyError::ChallengeGenerationError(msg) =>
                AppError::InternalServerError(format!("Failed to generate challenge: {}", msg)),
            PasskeyError::InternalServerError(msg) =>
                AppError::InternalServerError(msg),
        }
    }
}

// Add From<ApiError> implementations for domain-specific errors
impl From<ApiError> for RoleError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::NotFound(_) => RoleError::NotFound(Uuid::new()),
            ApiError::BadRequest(msg) => RoleError::DatabaseError(msg),
            ApiError::Forbidden(_) => RoleError::SystemRoleModification,
            ApiError::Unauthorized(_) => RoleError::SystemRoleModification,
            ApiError::InternalError(msg) => RoleError::InternalServerError(msg),
            ApiError::AppError(err) => err.into(),
        }
    }
}

impl From<ApiError> for OAuthApplicationError {
    fn from(error: ApiError) -> Self {
        match error {
            ApiError::NotFound(_) => OAuthApplicationError::NotFound(Uuid::new()),
            ApiError::BadRequest(msg) => OAuthApplicationError::InvalidData(msg),
            ApiError::Forbidden(msg) => OAuthApplicationError::InvalidData(msg),
            ApiError::Unauthorized(msg) => OAuthApplicationError::InvalidData(msg),
            ApiError::InternalError(msg) => OAuthApplicationError::InternalServerError(msg),
            ApiError::AppError(err) => err.into(),
        }
    }
}

impl From<PasskeyError> for ApiError {
    fn from(error: PasskeyError) -> Self {
        match error {
            PasskeyError::ChallengeNotFound => ApiError::BadRequest("Challenge not found or expired".to_string()),
            PasskeyError::InvalidChallenge => ApiError::BadRequest("Invalid challenge".to_string()),
            PasskeyError::ChallengeExpired => ApiError::BadRequest("Challenge expired".to_string()),
            PasskeyError::InvalidCredentialId => ApiError::BadRequest("Invalid credential ID".to_string()),
            PasskeyError::InvalidPublicKey => ApiError::BadRequest("Invalid public key format".to_string()),
            PasskeyError::CredentialNotFound => ApiError::BadRequest("Credential ID not found for user".to_string()),
            PasskeyError::PasskeyAlreadyRegistered => ApiError::BadRequest("Passkey already registered for this user".to_string()),
            PasskeyError::ReplayAttack => ApiError::BadRequest("Possible replay attack detected".to_string()),
            PasskeyError::UserNotFound => ApiError::BadRequest("No user associated with this challenge".to_string()),
            PasskeyError::DatabaseError(msg) => ApiError::InternalError(format!("Database error: {}", msg)),
            PasskeyError::UpdateError(msg) => ApiError::InternalError(format!("Failed to update passkey: {}", msg)),
            PasskeyError::ChallengeGenerationError(msg) => ApiError::InternalError(format!("Failed to generate challenge: {}", msg)),
            PasskeyError::InternalServerError(msg) => ApiError::InternalError(msg),
        }
    }
}

impl From<UserError> for ApiError {
    fn from(error: UserError) -> Self {
        match error {
            UserError::NotFound(id) => ApiError::NotFound(format!("User with ID {} not found", id)),
            UserError::EmailAlreadyExists(email) => ApiError::BadRequest(format!("User with email {} already exists", email)),
            UserError::InvalidUuid(msg) => ApiError::BadRequest(format!("Invalid UUID: {}", msg)),
            UserError::MissingPermissions => ApiError::Forbidden("Missing permissions to perform this action".to_string()),
            UserError::SystemUserModification => ApiError::Forbidden("Cannot modify system user".to_string()),
            UserError::PasswordHashingError => ApiError::InternalError("Error during password hashing".to_string()),
            UserError::AdminRoleAssignment => ApiError::Forbidden("Only system admin can assign admin role".to_string()),
            UserError::RoleNotFound(id) => ApiError::BadRequest(format!("Role with ID {} does not exist", id)),
            UserError::UserDisabled => ApiError::Forbidden("User is disabled".to_string()),
            UserError::NoUpdatesApplied => ApiError::BadRequest("No updates applied to user".to_string()),
            UserError::DatabaseError(msg) => ApiError::InternalError(format!("Database error: {}", msg)),
            UserError::InternalServerError(msg) => ApiError::InternalError(format!("Internal server error: {}", msg)),
            UserError::FirstNameRequired => ApiError::BadRequest("First name is required".to_string()),
            UserError::PasswordToShort => ApiError::BadRequest("Password too short".to_string()),
            UserError::InvalidEmail => ApiError::BadRequest("Invalid email".to_string()),
            UserError::PasskeyNotFound(id) => ApiError::NotFound(format!("Passkey with ID {} not found", id)),
            UserError::PasswordNotSet => ApiError::BadRequest("Password not set for this user".to_string()),
        }
    }
}
