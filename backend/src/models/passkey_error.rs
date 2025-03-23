use crate::models::http_response::HttpResponse;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PasskeyError {
    #[error("Challenge not found or expired")]
    ChallengeNotFound,

    #[error("Invalid challenge")]
    InvalidChallenge,

    #[error("Challenge expired")]
    ChallengeExpired,

    #[error("Invalid credential ID")]
    InvalidCredentialId,

    #[error("Invalid public key format")]
    InvalidPublicKey,

    #[error("Credential ID not found for user")]
    CredentialNotFound,

    #[error("Passkey already registered")]
    PasskeyAlreadyRegistered,

    #[error("Possible replay attack detected")]
    ReplayAttack,

    #[error("User not associated with challenge")]
    UserNotFound,

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Failed to update passkey: {0}")]
    UpdateError(String),

    #[error("Failed to generate challenge: {0}")]
    ChallengeGenerationError(String),

    #[error("Internal server error: {0}")]
    InternalServerError(String),
}

// Implement conversion from PasskeyError to HttpResponse
impl<T> From<PasskeyError> for HttpResponse<T> {
    fn from(error: PasskeyError) -> Self {
        match error {
            PasskeyError::ChallengeNotFound => HttpResponse {
                status: 400,
                message: "Challenge not found or expired".to_string(),
                data: None,
            },
            PasskeyError::InvalidChallenge => HttpResponse {
                status: 400,
                message: "Invalid challenge".to_string(),
                data: None,
            },
            PasskeyError::ChallengeExpired => HttpResponse {
                status: 400,
                message: "Challenge expired".to_string(),
                data: None,
            },
            PasskeyError::InvalidCredentialId => HttpResponse {
                status: 400,
                message: "Invalid credential ID".to_string(),
                data: None,
            },
            PasskeyError::InvalidPublicKey => HttpResponse {
                status: 400,
                message: "Invalid public key format".to_string(),
                data: None,
            },
            PasskeyError::CredentialNotFound => HttpResponse {
                status: 400,
                message: "Credential ID not found for user".to_string(),
                data: None,
            },
            PasskeyError::PasskeyAlreadyRegistered => HttpResponse {
                status: 400,
                message: "Passkey already registered for this user".to_string(),
                data: None,
            },
            PasskeyError::ReplayAttack => HttpResponse {
                status: 400,
                message: "Possible replay attack detected".to_string(),
                data: None,
            },
            PasskeyError::UserNotFound => HttpResponse {
                status: 400,
                message: "No user associated with this challenge".to_string(),
                data: None,
            },
            PasskeyError::DatabaseError(msg) => HttpResponse {
                status: 500,
                message: format!("Database error: {}", msg),
                data: None,
            },
            PasskeyError::UpdateError(msg) => HttpResponse {
                status: 500,
                message: format!("Failed to update passkey: {}", msg),
                data: None,
            },
            PasskeyError::ChallengeGenerationError(msg) => HttpResponse {
                status: 500,
                message: format!("Failed to generate challenge: {}", msg),
                data: None,
            },
            PasskeyError::InternalServerError(msg) => HttpResponse {
                status: 500,
                message: format!("Internal server error: {}", msg),
                data: None,
            },
        }
    }
}

// Define a Result type alias for passkey operations
pub type PasskeyResult<T> = Result<T, PasskeyError>; 