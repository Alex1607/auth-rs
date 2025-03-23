use rocket::http::Status;
use rocket::{
    post,
    serde::{json::Json, Deserialize, Serialize},
};
use rocket_db_pools::Connection;

use crate::auth::passkey::{PasskeyHandler, PasskeyOperation};
use crate::auth::auth::AuthEntity;
use crate::db::AuthRsDatabase;
use crate::errors::{ApiError, ApiResult};
use crate::models::http_response::HttpResponse;
use crate::models::passkey_error::PasskeyError;
use crate::models::user::{User, UserDTO, PasskeyDTO};
use crate::utils::response::json_response;

// Data structures for registration
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct StartRegistrationRequest {
    pub passkey_name: String,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct StartRegistrationResponse {
    pub challenge_id: String,
    pub challenge: String,
    pub user_id: String,
    pub user_name: String,
    pub passkey_name: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct FinishRegistrationRequest {
    pub challenge_id: String,
    pub challenge: String,
    pub credential_id: String,
    pub public_key: String,
    pub client_data: String,
    pub attestation_object: String,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct FinishRegistrationResponse {
    pub passkey: PasskeyDTO,
    pub user: UserDTO,
}

// Data structures for authentication
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct StartAuthenticationRequest {
    pub email: Option<String>, // Optional email for the user to authenticate
    pub credential_id: Option<String>, // Optional credential ID if user already chose a specific passkey
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct StartAuthenticationResponse {
    pub challenge_id: String,
    pub challenge: String,
    pub user_id: Option<String>, // Optional user ID if email was provided
    pub user_name: Option<String>, // Optional user name if email was provided
    pub allow_credentials: Option<Vec<String>>, // Optional list of allowed credential IDs if email was provided
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct FinishAuthenticationRequest {
    pub challenge_id: String,
    pub challenge: String,
    pub credential_id: String,
    pub authenticator_data: String,
    pub signature: String,
    pub client_data: String,
    pub user_handle: Option<String>, // User ID if known
    pub counter: u32,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct FinishAuthenticationResponse {
    pub token: String,
    pub user: UserDTO,
}

// Process start registration and return a Result
async fn process_start_registration(
    data: StartRegistrationRequest,
    auth: AuthEntity,
    _db: Connection<AuthRsDatabase>,
) -> ApiResult<StartRegistrationResponse> {
    // Verify user is authenticated (can only register passkeys if logged in)
    let user = auth.user()?;

    // Generate a challenge for registration
    let challenge = PasskeyHandler::generate_challenge(
        PasskeyOperation::Registration,
        Some(user.clone()),
    )
    .await
    .map_err(|err| PasskeyError::ChallengeGenerationError(err.to_string()))?;

    // Create registration response
    let response = StartRegistrationResponse {
        challenge_id: challenge.challenge_id,
        challenge: challenge.challenge,
        user_id: user.id.to_string(),
        user_name: format!("{} {}", user.first_name, user.last_name),
        passkey_name: data.passkey_name.clone(),
    };

    Ok(response)
}

// Start registration route
#[post("/auth/passkey/register/start", format = "json", data = "<data>")]
pub async fn start_registration(
    data: Json<StartRegistrationRequest>,
    auth: AuthEntity,
    db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<StartRegistrationResponse>>) {
    let data = data.into_inner();
    
    match process_start_registration(data, auth, db).await {
        Ok(response) => json_response(HttpResponse::success(
            "Passkey registration initiated",
            response,
        )),
        Err(err) => json_response(err.into()),
    }
}

// Process finish registration and return a Result
async fn process_finish_registration(
    data: FinishRegistrationRequest,
    _db: Connection<AuthRsDatabase>,
) -> ApiResult<FinishRegistrationResponse> {
    // Retrieve the challenge
    let challenge = PasskeyHandler::get_challenge_by_id(&data.challenge_id)
        .await
        .ok_or(PasskeyError::ChallengeNotFound)?;

    // Verify the challenge
    if !PasskeyHandler::is_challenge_valid(&challenge, &data.challenge) {
        return Err(PasskeyError::InvalidChallenge.into());
    }

    // Get the user from the challenge
    let mut user = challenge.user.ok_or(PasskeyError::UserNotFound)?;

    // Verify registration data
    match PasskeyHandler::verify_registration(
        &data.credential_id,
        &data.public_key,
        &data.challenge,
        &data.client_data,
        &data.attestation_object,
    ) {
        Ok(true) => {
            // Registration was successful - add the passkey to the user
            let passkey_name = match user
                .passkeys
                .as_ref()
                .map(|keys| keys.iter().find(|p| p.credential_id == data.credential_id))
            {
                Some(Some(_)) => {
                    // Passkey already exists
                    return Err(PasskeyError::PasskeyAlreadyRegistered.into());
                }
                _ => "My Passkey".to_string(), // Default name if not found in challenge data
            };

            // Add the passkey to the user
            let passkey = user
                .add_passkey(
                    passkey_name,
                    data.public_key.clone(),
                    data.credential_id.clone(),
                    &_db,
                )
                .await
                .map_err(|err| PasskeyError::DatabaseError(err.to_string()))?;

            // Clean up the challenge
            PasskeyHandler::remove_challenge(&data.challenge_id).await;

            // Return success with the passkey
            let passkey_dto = PasskeyDTO {
                id: passkey.id,
                name: passkey.name,
                created_at: passkey.created_at,
                last_used: passkey.last_used,
            };

            Ok(FinishRegistrationResponse {
                passkey: passkey_dto,
                user: user.to_dto(),
            })
        }
        Ok(false) => {
            Err(PasskeyError::InvalidPublicKey.into())
        }
        Err(err) => Err(PasskeyError::InternalServerError(format!("Registration error: {}", err)).into()),
    }
}

// Finish registration route
#[post("/auth/passkey/register/finish", format = "json", data = "<data>")]
pub async fn finish_registration(
    data: Json<FinishRegistrationRequest>,
    db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<FinishRegistrationResponse>>) {
    let data = data.into_inner();
    
    match process_finish_registration(data, db).await {
        Ok(response) => json_response(HttpResponse::success(
            "Passkey registered successfully",
            response,
        )),
        Err(err) => json_response(err.into()),
    }
}

// Process start authentication and return a Result
async fn process_start_authentication(
    data: StartAuthenticationRequest,
    db: Connection<AuthRsDatabase>,
) -> ApiResult<StartAuthenticationResponse> {
    // We can either find a user by email or by credential ID
    let user = if let Some(email) = &data.email {
        // Find user by email
        match User::get_by_email(email, &db).await {
            Ok(user) => {
                if user.disabled {
                    return Err(ApiError::Forbidden("User account is disabled".to_string()));
                }
                Some(user)
            }
            Err(_) => {
                // We don't want to leak information about whether an email exists, so always return a challenge
                None
            }
        }
    } else if let Some(credential_id) = &data.credential_id {
        // Find user by credential ID
        // In a real implementation, you would query the database for a user with this credential ID
        match User::get_all(&db).await {
            Ok(users) => {
                let mut found_user = None;
                for u in users {
                    if let Some(_) = u.get_passkey_by_credential_id(credential_id) {
                        if u.disabled {
                            return Err(ApiError::Forbidden("User account is disabled".to_string()));
                        }
                        found_user = Some(u);
                        break;
                    }
                }
                found_user
            }
            Err(err) => {
                return Err(PasskeyError::DatabaseError(format!("Failed to search for users: {}", err)).into());
            }
        }
    } else {
        // Neither email nor credential ID provided
        return Err(ApiError::BadRequest("Either email or credential ID must be provided".to_string()));
    };

    // Generate a challenge for authentication
    let challenge = PasskeyHandler::generate_challenge(
        PasskeyOperation::Authentication,
        user.clone(),
    )
    .await
    .map_err(|err| PasskeyError::ChallengeGenerationError(err.to_string()))?;

    // Create authentication response
    let mut response = StartAuthenticationResponse {
        challenge_id: challenge.challenge_id,
        challenge: challenge.challenge,
        user_id: None,
        user_name: None,
        allow_credentials: None,
    };

    // If the user was found and has passkeys, provide the credential IDs
    if let Some(user) = user {
        response.user_id = Some(user.id.to_string());
        response.user_name = Some(format!("{} {}", user.first_name, user.last_name));

        if let Some(passkeys) = &user.passkeys {
            if !passkeys.is_empty() {
                response.allow_credentials = Some(
                    passkeys
                        .iter()
                        .map(|p| p.credential_id.clone())
                        .collect(),
                );
            }
        }
    }

    Ok(response)
}

// Start authentication route
#[post("/auth/passkey/login/start", format = "json", data = "<data>")]
pub async fn start_authentication(
    data: Json<StartAuthenticationRequest>,
    db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<StartAuthenticationResponse>>) {
    let data = data.into_inner();
    
    match process_start_authentication(data, db).await {
        Ok(response) => json_response(HttpResponse::success(
            "Passkey authentication initiated",
            response,
        )),
        Err(err) => json_response(err.into()),
    }
}

// Process finish authentication and return a Result
async fn process_finish_authentication(
    data: FinishAuthenticationRequest,
    db: Connection<AuthRsDatabase>,
) -> ApiResult<FinishAuthenticationResponse> {
    // Retrieve the challenge
    let challenge = PasskeyHandler::get_challenge_by_id(&data.challenge_id)
        .await
        .ok_or(PasskeyError::ChallengeNotFound)?;

    // Verify the challenge
    if !PasskeyHandler::is_challenge_valid(&challenge, &data.challenge) {
        return Err(PasskeyError::InvalidChallenge.into());
    }

    // Find the user with this credential ID
    let mut user = if let Some(user) = challenge.user.clone() {
        // Verify this user has the credential
        if user.get_passkey_by_credential_id(&data.credential_id).is_none() {
            return Err(PasskeyError::CredentialNotFound.into());
        }
        user
    } else {
        // Find any user with this credential ID
        // In a real implementation, you would query the database to find a user with this credential ID
        // For this implementation, we'll do a scan of all users
        match User::get_all(&db).await {
            Ok(users) => {
                let mut found_user = None;
                for u in users {
                    if let Some(_passkey) = u.get_passkey_by_credential_id(&data.credential_id) {
                        found_user = Some(u);
                        break;
                    }
                }

                found_user.ok_or(PasskeyError::CredentialNotFound)?
            }
            Err(err) => {
                return Err(PasskeyError::DatabaseError(format!("Failed to search for users: {}", err)).into());
            }
        }
    };

    if user.disabled {
        return Err(ApiError::Forbidden("User account is disabled".to_string()));
    }

    // Verify authentication data
    match PasskeyHandler::verify_authentication(
        &data.credential_id,
        &data.challenge,
        &data.signature,
        &data.client_data,
        &data.authenticator_data,
        &user,
        data.counter,
    ) {
        Ok(true) => {
            // Authentication was successful - update the passkey counter
            user.update_passkey_counter(&data.credential_id, data.counter, &db)
                .await
                .map_err(|err| PasskeyError::UpdateError(format!("Failed to update passkey counter: {}", err)))?;

            // Generate a new token for the user
            let new_token = User::generate_token();
            let _old_token = user.token.clone();
            user.token = new_token.clone();

            // Update the user
            user.update(&db).await
                .map_err(|err| PasskeyError::UpdateError(format!("Failed to update user token: {}", err)))?;

            // Clean up the challenge
            PasskeyHandler::remove_challenge(&data.challenge_id).await;

            // Return success with the user's token
            Ok(FinishAuthenticationResponse {
                token: new_token,
                user: user.to_dto(),
            })
        }
        Ok(false) => {
            Err(PasskeyError::InvalidPublicKey.into())
        }
        Err(err) => Err(PasskeyError::InternalServerError(format!("Authentication error: {}", err)).into()),
    }
}

// Finish authentication route
#[post("/auth/passkey/login/finish", format = "json", data = "<data>")]
pub async fn finish_authentication(
    data: Json<FinishAuthenticationRequest>,
    db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<FinishAuthenticationResponse>>) {
    let data = data.into_inner();
    
    match process_finish_authentication(data, db).await {
        Ok(response) => json_response(HttpResponse::success(
            "Authentication successful",
            response,
        )),
        Err(err) => json_response(err.into()),
    }
}

// Process list passkeys and return a Result
async fn process_list_passkeys(
    auth: AuthEntity,
    _db: Connection<AuthRsDatabase>,
) -> ApiResult<Vec<PasskeyDTO>> {
    // Verify user is authenticated
    let user = auth.user()?;

    // Get the user's passkeys
    let passkeys = match &user.passkeys {
        Some(passkeys) => passkeys
            .iter()
            .map(|p| PasskeyDTO {
                id: p.id.clone(),
                name: p.name.clone(),
                created_at: p.created_at,
                last_used: p.last_used,
            })
            .collect(),
        None => Vec::new(),
    };

    Ok(passkeys)
}

// Get user's passkeys
#[post("/auth/passkey/list", format = "json")]
pub async fn list_passkeys(
    auth: AuthEntity,
    db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<Vec<PasskeyDTO>>>) {
    match process_list_passkeys(auth, db).await {
        Ok(passkeys) => json_response(HttpResponse::success("User passkeys", passkeys)),
        Err(err) => json_response(err.into()),
    }
}

// Process remove passkey and return a Result
async fn process_remove_passkey(
    auth: AuthEntity,
    db: Connection<AuthRsDatabase>,
    passkey_id: String,
) -> ApiResult<UserDTO> {
    // Verify user is authenticated
    let user_id = auth.user_id;
    let mut user = User::get_by_id(user_id, &db).await
        .map_err(|err| ApiError::from(err))?;

    // Remove the passkey
    user.remove_passkey(&passkey_id, &db)
        .await
        .map_err(|err| PasskeyError::UpdateError(format!("Failed to remove passkey: {}", err)))?;
    
    Ok(user.to_dto())
}

// Remove a passkey
#[post("/auth/passkey/remove", format = "json", data = "<data>")]
pub async fn remove_passkey(
    auth: AuthEntity,
    db: Connection<AuthRsDatabase>,
    data: Json<String>,
) -> (Status, Json<HttpResponse<UserDTO>>) {
    let passkey_id = data.into_inner();
    
    match process_remove_passkey(auth, db, passkey_id).await {
        Ok(user) => json_response(HttpResponse::success(
            "Passkey removed successfully",
            user,
        )),
        Err(err) => json_response(err.into()),
    }
} 