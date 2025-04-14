use mongodb::bson::Uuid;
use rocket::{
    delete, get,
    http::Status,
    patch,
    serde::{json::Json, Deserialize},
};
use rocket_db_pools::Connection;

use crate::{
    auth::AuthEntity,
    db::AuthRsDatabase,
    errors::{ApiError, ApiResult, AppError},
    models::{http_response::HttpResponse, passkey::PasskeyDTO, user::User},
    utils::response::json_response,
};
use crate::models::passkey::Passkey;

// DTO for updating passkey metadata
#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct PasskeyUpdateRequest {
    pub name: Option<String>,
}

// 1. List User's Passkeys
#[get("/users/<user_id>/passkeys")]
pub async fn list_passkeys(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    user_id: String,
) -> (Status, Json<HttpResponse<Vec<PasskeyDTO>>>) {
    let user_uuid = match Uuid::parse_str(&user_id) {
        Ok(id) => id,
        Err(_) => return json_response(ApiError::InvalidUUID.into()),
    };

    // Verify that the user ID in the request matches the authenticated user's ID
    if user_uuid != req_entity.user_id {
        return json_response(
            ApiError::Unauthorized("Cannot access passkeys for another user".to_string()).into(),
        );
    }

    match get_all_passkeys_for_user(db, req_entity).await {
        Ok(passkeys) => json_response(HttpResponse {
            status: 200,
            message: "Passkeys retrieved successfully".to_string(),
            data: Some(passkeys),
        }),
        Err(err) => json_response(err.into()),
    }
}

async fn get_all_passkeys_for_user(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
) -> ApiResult<Vec<PasskeyDTO>> {
    // Get the authenticated user
    let passkeys = Passkey::get_by_owner(req_entity.user_id, &db)
        .await
        .map_err(|e| ApiError::NotFound(format!("User not found: {}", e)))?
        .iter().map(|passkey| passkey.to_dto())
        .collect();

    Ok(passkeys)
}
