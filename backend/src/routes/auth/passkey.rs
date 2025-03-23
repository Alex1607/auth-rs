use rocket::http::Status;
use rocket::{
    post,
    serde::{json::Json, Deserialize, Serialize},
};
use rocket_db_pools::Connection;

use crate::auth::passkey::{PasskeyHandler, PasskeyOperation};
use crate::auth::auth::AuthEntity;
use crate::db::AuthRsDatabase;
use crate::models::http_response::HttpResponse;
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

// Start registration route
#[post("/auth/passkey/register/start", format = "json", data = "<data>")]
pub async fn start_registration(
    data: Json<StartRegistrationRequest>,
    auth: AuthEntity,
    db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<StartRegistrationResponse>>) {
    // Verify user is authenticated (can only register passkeys if logged in)
    let user = match auth.user() {
        Ok(user) => user,
        Err(_) => {
            return json_response(HttpResponse::<StartRegistrationResponse>::error(
                401,
                "Authentication required",
                None,
            ))
        }
    };

    // Generate a challenge for registration
    let challenge = match PasskeyHandler::generate_challenge(
        PasskeyOperation::Registration,
        Some(user.clone()),
    )
    .await
    {
        Ok(challenge) => challenge,
        Err(err) => {
            return json_response(HttpResponse::<StartRegistrationResponse>::error(
                500,
                &format!("Failed to generate challenge: {}", err),
                None,
            ))
        }
    };

    // Create registration response
    let response = StartRegistrationResponse {
        challenge_id: challenge.challenge_id,
        challenge: challenge.challenge,
        user_id: user.id.to_string(),
        user_name: format!("{} {}", user.first_name, user.last_name),
        passkey_name: data.passkey_name.clone(),
    };

    json_response(HttpResponse::success(
        "Passkey registration initiated",
        response,
    ))
}

// Finish registration route
#[post("/auth/passkey/register/finish", format = "json", data = "<data>")]
pub async fn finish_registration(
    data: Json<FinishRegistrationRequest>,
    _db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<FinishRegistrationResponse>>) {
    // Retrieve the challenge
    let challenge = match PasskeyHandler::get_challenge_by_id(&data.challenge_id).await {
        Some(challenge) => challenge,
        None => {
            return json_response(HttpResponse::<FinishRegistrationResponse>::error(
                400,
                "Invalid or expired challenge",
                None,
            ))
        }
    };

    // Verify the challenge
    if !PasskeyHandler::is_challenge_valid(&challenge, &data.challenge) {
        return json_response(HttpResponse::<FinishRegistrationResponse>::error(
            400,
            "Invalid challenge response",
            None,
        ));
    }

    // Get the user from the challenge
    let mut user = match challenge.user {
        Some(user) => user,
        None => {
            return json_response(HttpResponse::<FinishRegistrationResponse>::error(
                400,
                "No user associated with this challenge",
                None,
            ))
        }
    };

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
                    return json_response(HttpResponse::<FinishRegistrationResponse>::error(
                        400,
                        "Passkey already registered for this user",
                        None,
                    ));
                }
                _ => "My Passkey".to_string(), // Default name if not found in challenge data
            };

            // Add the passkey to the user
            let passkey = match user
                .add_passkey(
                    passkey_name,
                    data.public_key.clone(),
                    data.credential_id.clone(),
                    &_db,
                )
                .await
            {
                Ok(passkey) => passkey,
                Err(err) => {
                    return json_response(HttpResponse::<FinishRegistrationResponse>::error(
                        500,
                        &format!("Failed to add passkey: {}", err),
                        None,
                    ))
                }
            };

            // Clean up the challenge
            PasskeyHandler::remove_challenge(&data.challenge_id).await;

            // Return success with the passkey
            let passkey_dto = PasskeyDTO {
                id: passkey.id,
                name: passkey.name,
                created_at: passkey.created_at,
                last_used: passkey.last_used,
            };

            json_response(HttpResponse::success(
                "Passkey registered successfully",
                FinishRegistrationResponse {
                    passkey: passkey_dto,
                    user: user.to_dto(),
                },
            ))
        }
        Ok(false) => {
            json_response(HttpResponse::<FinishRegistrationResponse>::error(
                400,
                "Registration verification failed",
                None,
            ))
        }
        Err(err) => json_response(HttpResponse::<FinishRegistrationResponse>::error(
            400,
            &format!("Registration error: {}", err),
            None,
        )),
    }
}

// Start authentication route
#[post("/auth/passkey/login/start", format = "json", data = "<data>")]
pub async fn start_authentication(
    data: Json<StartAuthenticationRequest>,
    _db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<StartAuthenticationResponse>>) {
    // If email is provided, find the user to get their credentials
    let user = if let Some(email) = &data.email {
        match User::get_by_email(email, &_db).await {
            Ok(user) => {
                if user.disabled {
                    return json_response(HttpResponse::<StartAuthenticationResponse>::error(
                        403,
                        "User account is disabled",
                        None,
                    ));
                }
                Some(user)
            }
            Err(_) => {
                // We don't want to leak information about whether an email exists, so always return a challenge
                None
            }
        }
    } else {
        None
    };

    // Generate a challenge for authentication
    let challenge = match PasskeyHandler::generate_challenge(
        PasskeyOperation::Authentication,
        user.clone(),
    )
    .await
    {
        Ok(challenge) => challenge,
        Err(err) => {
            return json_response(HttpResponse::<StartAuthenticationResponse>::error(
                500,
                &format!("Failed to generate challenge: {}", err),
                None,
            ))
        }
    };

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

    json_response(HttpResponse::success(
        "Passkey authentication initiated",
        response,
    ))
}

// Finish authentication route
#[post("/auth/passkey/login/finish", format = "json", data = "<data>")]
pub async fn finish_authentication(
    data: Json<FinishAuthenticationRequest>,
    db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<FinishAuthenticationResponse>>) {
    // Retrieve the challenge
    let challenge = match PasskeyHandler::get_challenge_by_id(&data.challenge_id).await {
        Some(challenge) => challenge,
        None => {
            return json_response(HttpResponse::<FinishAuthenticationResponse>::error(
                400,
                "Invalid or expired challenge",
                None,
            ))
        }
    };

    // Verify the challenge
    if !PasskeyHandler::is_challenge_valid(&challenge, &data.challenge) {
        return json_response(HttpResponse::<FinishAuthenticationResponse>::error(
            400,
            "Invalid challenge response",
            None,
        ));
    }

    // Find the user with this credential ID
    let mut user = if let Some(user) = challenge.user.clone() {
        // Verify this user has the credential
        if user.get_passkey_by_credential_id(&data.credential_id).is_none() {
            return json_response(HttpResponse::<FinishAuthenticationResponse>::error(
                400,
                "Credential not found for this user",
                None,
            ));
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

                match found_user {
                    Some(u) => u,
                    None => {
                        return json_response(HttpResponse::<FinishAuthenticationResponse>::error(
                            400,
                            "No user found with this credential",
                            None,
                        ));
                    }
                }
            }
            Err(_) => {
                return json_response(HttpResponse::<FinishAuthenticationResponse>::error(
                    500,
                    "Failed to search for users",
                    None,
                ));
            }
        }
    };

    if user.disabled {
        return json_response(HttpResponse::<FinishAuthenticationResponse>::error(
            403,
            "User account is disabled",
            None,
        ));
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
            if let Err(err) = user
                .update_passkey_counter(&data.credential_id, data.counter, &db)
                .await
            {
                return json_response(HttpResponse::<FinishAuthenticationResponse>::error(
                    500,
                    &format!("Failed to update passkey counter: {}", err),
                    None,
                ));
            }

            // Generate a new token for the user
            let new_token = User::generate_token();
            let _old_token = user.token.clone();
            user.token = new_token.clone();

            // Update the user
            if let Err(err) = user.update(&db).await {
                return json_response(HttpResponse::<FinishAuthenticationResponse>::error(
                    500,
                    &format!("Failed to update user token: {}", err),
                    None,
                ));
            }

            // Clean up the challenge
            PasskeyHandler::remove_challenge(&data.challenge_id).await;

            // Return success with the user's token
            json_response(HttpResponse::success(
                "Authentication successful",
                FinishAuthenticationResponse {
                    token: new_token,
                    user: user.to_dto(),
                },
            ))
        }
        Ok(false) => {
            json_response(HttpResponse::<FinishAuthenticationResponse>::error(
                400,
                "Authentication verification failed",
                None,
            ))
        }
        Err(err) => json_response(HttpResponse::<FinishAuthenticationResponse>::error(
            400,
            &format!("Authentication error: {}", err),
            None,
        )),
    }
}

// Get user's passkeys
#[post("/auth/passkey/list", format = "json")]
pub async fn list_passkeys(
    auth: AuthEntity,
    _db: Connection<AuthRsDatabase>,
) -> (Status, Json<HttpResponse<Vec<PasskeyDTO>>>) {
    // Verify user is authenticated
    let user = match auth.user() {
        Ok(user) => user,
        Err(_) => {
            return json_response(HttpResponse::<Vec<PasskeyDTO>>::error(
                401,
                "Authentication required",
                None,
            ))
        }
    };

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

    json_response(HttpResponse::success("User passkeys", passkeys))
}

// Remove a passkey
#[post("/auth/passkey/remove", format = "json", data = "<data>")]
pub async fn remove_passkey(
    auth: AuthEntity,
    db: Connection<AuthRsDatabase>,
    data: Json<String>,
) -> (Status, Json<HttpResponse<UserDTO>>) {
    // Verify user is authenticated
    let user_id = auth.user_id;
    let mut user = match User::get_by_id(user_id, &db).await {
        Ok(user) => user,
        Err(_) => {
            return json_response(HttpResponse::<UserDTO>::error(
                401,
                "Authentication required",
                None,
            ))
        }
    };

    // Remove the passkey
    let passkey_id = data.into_inner();
    match user.remove_passkey(&passkey_id, &db).await {
        Ok(_) => json_response(HttpResponse::success(
            "Passkey removed successfully",
            user.to_dto(),
        )),
        Err(err) => json_response(HttpResponse::<UserDTO>::error(
            400,
            &format!("Failed to remove passkey: {}", err),
            None,
        )),
    }
} 