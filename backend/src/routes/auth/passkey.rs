use crate::models::passkey::Passkey;
use crate::AUTHENTICATIONS;
use crate::{
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult, AppError},
    models::{
        audit_log::{AuditLog, AuditLogAction, AuditLogEntityType},
        http_response::HttpResponse,
        user::{User, UserDTO},
    },
    utils::response::json_response,
};
use lazy_static::lazy_static;
use mongodb::bson::Uuid;
use rocket::{
    get,
    http::Status,
    post,
    serde::{json::Json, Deserialize, Serialize},
};
use rocket_db_pools::Connection;
use std::env;
use std::sync::Arc;
use url::Url;
use webauthn_rs::prelude::{DiscoverableKey, PublicKeyCredential, RequestChallengeResponse};
use webauthn_rs::{Webauthn, WebauthnBuilder};

// Static Webauthn instance with configurable values
lazy_static! {
    static ref WEBAUTHN: Arc<Webauthn> = {
        // Get configuration from environment variables or use defaults
        let rp_id = env::var("WEBAUTHN_RP_ID").unwrap_or_else(|_| "localhost".to_string());
        let rp_origin_str = env::var("WEBAUTHN_RP_ORIGIN")
            .unwrap_or_else(|_| format!("http://{}", rp_id));
        let rp_name = env::var("WEBAUTHN_RP_NAME").unwrap_or_else(|_| "auth-rs".to_string());

        let rp_origin = Url::parse(&rp_origin_str)
            .expect("Invalid WEBAUTHN_RP_ORIGIN URL");

        let webauthn = WebauthnBuilder::new(&rp_id, &rp_origin)
            .expect("Invalid Webauthn configuration")
            .rp_name(&rp_name)
            .allow_subdomains(true)
            .allow_any_port(true)
            .build()
            .expect("Failed to build Webauthn instance");

        Arc::new(webauthn)
    };
}

// Return a reference to the static Webauthn instance
pub fn get_webauthn() -> &'static Webauthn {
    &WEBAUTHN
}

// DTO for passkey authentication finish request
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticateFinishRequest {
    pub authentication_id: Uuid,
    pub credential: PublicKeyCredential,
}

// Response for passkey authentication start
#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticateStartResponse {
    pub challenge: RequestChallengeResponse,
    pub authentication_id: Uuid,
}

// Response for passkey authentication finish
#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyAuthenticateFinishResponse {
    pub user: UserDTO,
    pub token: String,
}

#[get("/auth/passkeys/authenticate/start")]
pub async fn authenticate_start() -> (Status, Json<HttpResponse<PasskeyAuthenticateStartResponse>>)
{
    match process_authenticate_start().await {
        Ok(response) => json_response(HttpResponse {
            status: 200,
            message: "Authentication initiated".to_string(),
            data: Some(response),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_authenticate_start() -> ApiResult<PasskeyAuthenticateStartResponse> {
    // Initialize Webauthn
    let webauthn = get_webauthn();

    let (challenge, auth_state) = webauthn
        .start_discoverable_authentication()
        .map_err(|_| ApiError::AppError(AppError::WebauthnError))?;

    // Store authentication state
    let authentication_id = Uuid::new();
    AUTHENTICATIONS
        .lock()
        .await
        .insert(authentication_id, auth_state);

    Ok(PasskeyAuthenticateStartResponse {
        challenge,
        authentication_id,
    })
}

#[post("/auth/passkeys/authenticate/finish", format = "json", data = "<data>")]
pub async fn authenticate_finish(
    db: Connection<AuthRsDatabase>,
    data: Json<PasskeyAuthenticateFinishRequest>,
) -> (
    Status,
    Json<HttpResponse<PasskeyAuthenticateFinishResponse>>,
) {
    match process_authenticate_finish(db, data.into_inner()).await {
        Ok(response) => json_response(HttpResponse {
            status: 200,
            message: "Authentication successful".to_string(),
            data: Some(response),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn process_authenticate_finish(
    db: Connection<AuthRsDatabase>,
    data: PasskeyAuthenticateFinishRequest,
) -> ApiResult<PasskeyAuthenticateFinishResponse> {
    // Get the authentication state
    let auth_state = AUTHENTICATIONS
        .lock()
        .await
        .remove(&data.authentication_id)
        .ok_or(ApiError::InvalidState(
            "Authentication not found".to_string(),
        ))?;

    // Initialize Webauthn
    let webauthn = get_webauthn();

    // Find user with this credential
    let passkey = Passkey::get_by_id(&data.credential.id, &db)
        .await
        .map_err(|_| ApiError::NotFound("Passkey not found with this credential".to_string()))?;

    let user = User::get_by_id(passkey.owner, &db)
        .await
        .map_err(|_| ApiError::NotFound("User not found with this credential".to_string()))?;

    let all_passkeys = Passkey::get_by_owner(user.id, &db)
        .await
        .map_err(|_| ApiError::AppError(AppError::PasskeyNotFound(user.id)))?
        .iter()
        .map(|passkey| DiscoverableKey::from(passkey.credential.clone()))
        .collect::<Vec<_>>();

    // Verify authentication
    let _ = webauthn
        .finish_discoverable_authentication(&data.credential, auth_state, all_passkeys.as_slice())
        .map_err(|_| ApiError::AppError(AppError::WebauthnError))?;

    AuditLog::new(
        user.clone().id.to_string(),
        AuditLogEntityType::User,
        AuditLogAction::Login,
        format!("Passkey login successful.|{}", passkey.id),
        user.id,
        None,
        None,
    )
    .insert(&db)
    .await
    .ok();

    // Return success with user information and token
    Ok(PasskeyAuthenticateFinishResponse {
        user: user.to_dto(),
        token: user.token,
    })
}
