use mongodb::bson::Uuid;
use rocket::http::Status;
use rocket::{
    post,
    serde::{json::Json, Deserialize, Serialize},
};
use rocket_db_pools::Connection;

use crate::models::user::UserDTO;
use crate::utils::response::json_response;
use crate::{
    auth::mfa::MfaHandler,
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult},
    models::{http_response::HttpResponse, user::User},
};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct LoginData {
    pub email: String,
    pub password: Option<String>,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub user: Option<UserDTO>,
    pub token: Option<String>,
    pub mfa_required: bool,
    pub mfa_flow_id: Option<Uuid>,
    pub use_passkey: bool,
    pub has_passkeys: bool,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct AuthOptionsResponse {
    pub has_passkeys: bool,
    pub requires_mfa: bool,
}

// Process to check authentication options for a user
async fn get_auth_options(
    db: &Connection<AuthRsDatabase>,
    email: String,
) -> ApiResult<AuthOptionsResponse> {
    let user = User::get_by_email(&email, db)
        .await
        .map_err(|_| ApiError::NotFound("User not found".to_string()))?;

    if user.disabled {
        return Err(ApiError::Forbidden("User account is disabled".to_string()));
    }

    // Check what authentication methods the user has
    let has_passkeys = match &user.passkeys {
        Some(passkeys) => !passkeys.is_empty(),
        None => false,
    };
    let requires_mfa = MfaHandler::is_mfa_required(&user);

    Ok(AuthOptionsResponse {
        has_passkeys,
        requires_mfa,
    })
}

// Endpoint to discover authentication options
#[post("/auth/options", format = "json", data = "<data>")]
pub async fn auth_options(
    db: Connection<AuthRsDatabase>,
    data: Json<String>,
) -> (Status, Json<HttpResponse<AuthOptionsResponse>>) {
    let email = data.into_inner();
    
    match get_auth_options(&db, email).await {
        Ok(options) => json_response(HttpResponse::success(
            "Authentication options retrieved",
            options,
        )),
        Err(err) => json_response(err.into()),
    }
}

/// # Authentication Flow
/// This API supports multiple authentication methods:
/// 
/// 1. Traditional Password Flow:
///    - User provides email and password
///    - If MFA is enabled, user is prompted for MFA code
///    - On success, user receives a token
///
/// 2. Passkey Authentication Flow:
///    - User provides email (password is optional)
///    - If user has passkeys, they're prompted to use passkey authentication
///    - User completes passkey authentication via /auth/passkey/login endpoints
///    - On success, user receives a token
///
/// 3. Discovery Flow:
///    - User can check available authentication methods via /auth/options
///    - Based on the response, client can choose the appropriate auth method
///
/// The API is designed to be flexible, allowing users to authenticate with
/// either passwords, passkeys, or a combination of both plus MFA.
#[post("/auth/login", format = "json", data = "<data>")]
pub async fn login(
    db: Connection<AuthRsDatabase>,
    data: Json<LoginData>,
) -> (Status, Json<HttpResponse<LoginResponse>>) {
    let login_data = data.into_inner();

    match process_login(&db, login_data).await {
        Ok(response) => {
            let message = if response.mfa_required {
                "MFA required"
            } else if response.use_passkey {
                "Please use passkey authentication"
            } else {
                "Login successful"
            };
            json_response(HttpResponse::success(message, response))
        }
        Err(err) => json_response(err.into()),
    }
}

// Process login and return a Result
async fn process_login(
    db: &Connection<AuthRsDatabase>,
    login_data: LoginData,
) -> ApiResult<LoginResponse> {
    let user = User::get_by_email(&login_data.email, db)
        .await
        .map_err(|err| ApiError::InternalError(err.to_string()))?;

    if user.disabled {
        return Err(ApiError::Forbidden("User is disabled".to_string()));
    }

    // Check what authentication methods the user has
    let has_passkeys = match &user.passkeys {
        Some(passkeys) => !passkeys.is_empty(),
        None => false,
    };

    // If no password is provided, return auth options
    if login_data.password.is_none() {
        if has_passkeys {
            // Suggest using passkey authentication
            return Ok(LoginResponse {
                user: None,
                token: None,
                mfa_required: false,
                mfa_flow_id: None,
                use_passkey: true,
                has_passkeys,
            });
        } else {
            // User needs to provide a password
            return Err(ApiError::BadRequest("Password is required for this account".to_string()));
        }
    }

    // Password authentication flow
    let password = login_data.password.unwrap();
    
    // Verify the password
    if user.verify_password(&password).is_err() {
        return Err(ApiError::Unauthorized(
            "Invalid email or password".to_string(),
        ));
    }

    // Check if MFA is required
    if MfaHandler::is_mfa_required(&user) {
        let mfa_flow = MfaHandler::start_login_flow(&user)
            .await
            .map_err(|err| ApiError::InternalError(format!("Failed to start MFA flow: {}", err)))?;

        return Ok(LoginResponse {
            user: None,
            token: None,
            mfa_required: true,
            mfa_flow_id: Some(mfa_flow.flow_id),
            use_passkey: false,
            has_passkeys,
        });
    }

    // Password authentication successful, no MFA required
    return Ok(LoginResponse {
        user: Some(user.to_dto()),
        token: Some(user.token),
        mfa_required: false,
        mfa_flow_id: None,
        use_passkey: false,
        has_passkeys,
    });
}
