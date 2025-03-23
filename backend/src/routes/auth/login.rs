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
    pub password: String,
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

    // Check if the user has a password set
    match &user.password_hash {
        Some(_password_hash) => {
            // Verify the password
            if user.verify_password(&login_data.password).is_err() {
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
                });
            }

            // Password authentication successful, no MFA required
            Ok(LoginResponse {
                user: Some(user.to_dto()),
                token: Some(user.token),
                mfa_required: false,
                mfa_flow_id: None,
                use_passkey: false,
            })
        },
        None => {
            // User has no password set - check if they have passkeys
            let has_passkeys = match &user.passkeys {
                Some(passkeys) => !passkeys.is_empty(),
                None => false,
            };

            if has_passkeys {
                // Suggest using passkey authentication instead
                return Ok(LoginResponse {
                    user: None,
                    token: None,
                    mfa_required: false,
                    mfa_flow_id: None,
                    use_passkey: true,
                });
            } else {
                // No password and no passkeys - this account can't be logged into
                return Err(ApiError::Unauthorized(
                    "No authentication methods available for this account".to_string(),
                ));
            }
        }
    }
}

#[allow(unused)]
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
