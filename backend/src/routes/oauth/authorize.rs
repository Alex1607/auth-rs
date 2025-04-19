use mongodb::bson::Uuid;
use rand::{rng, thread_rng, Rng, RngCore};
use rocket::http::Status;
use rocket::{
    post,
    serde::{json::Json, Deserialize, Serialize},
    tokio,
};
use rocket_db_pools::Connection;

use crate::{
    auth::AuthEntity,
    db::AuthRsDatabase,
    models::{oauth_application::OAuthApplication, oauth_scope::OAuthScope},
    OAUTH_CODES,
};

use super::token::TokenOAuthData;

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeOAuthData {
    client_id: Uuid,
    redirect_uri: String,
    scope: Vec<OAuthScope>,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct AuthorizeOAuthResponse {
    pub client_id: Uuid,
    pub redirect_uri: String,
    // Authorization code (UUID string)
    pub code: String,
}

#[allow(unused)]
#[post("/oauth/authorize", format = "json", data = "<data>")]
pub async fn authorize_oauth_application(
    db: Connection<AuthRsDatabase>,
    req_entity: AuthEntity,
    data: Json<AuthorizeOAuthData>,
) -> (Status, Option<Json<AuthorizeOAuthResponse>>) {
    let data = data.into_inner();

    if !req_entity.is_user()
        || req_entity.user.as_ref().unwrap().disabled
        || req_entity.user.unwrap().is_system_admin()
    {
        eprintln!("User is not allowed to authorize applications");
        return (Status::Unauthorized, None);
    }

    if data.scope.is_empty() {
        return (Status::BadRequest, None);
    }

    let mut random_bytes = vec![0u8; 64];
    rng().fill_bytes(&mut random_bytes);
    let code = hex::encode(random_bytes);

    let oauth_application = match OAuthApplication::get_by_id(data.client_id, &db).await {
        Ok(app) => app,
        Err(err) => {
            eprintln!("Error getting oauth application: {:?}", err);
            return (Status::InternalServerError, None);
        }
    };

    if !oauth_application.redirect_uris.contains(&data.redirect_uri) {
        eprintln!("Redirect uri is not allowed for this application");
        return (Status::Forbidden, None);
    }

    let mut codes = OAUTH_CODES.lock().await;
    let code_key = code.clone();
    codes.insert(
        code_key,
        TokenOAuthData {
            client_id: oauth_application.id,
            client_secret: oauth_application.secret,
            user_id: Some(req_entity.user_id),
            code: code.clone(),
            scope: Some(data.scope),
            grant_type: "authorization_code".to_string(),
            redirect_uri: data.redirect_uri.clone(),
        },
    );
    drop(codes);

    //TODO: Store this state in the db with a timestamp, and check for expiration
    //  We can not and should not rely on the application not crashing or restarting
    //  This application should be completely stateless
    // delete code after 5 minutes
    let code_clone_for_task = code.clone(); // Clone the code for the task
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(300)).await;
        let mut codes = OAUTH_CODES.lock().await;
        // Use the cloned code inside the task
        codes.remove(&code_clone_for_task);
        drop(codes);
    });

    (
        Status::Ok,
        Some(Json(AuthorizeOAuthResponse {
            client_id: data.client_id,
            // return the same redirect URI
            redirect_uri: data.redirect_uri.clone(),
            // Use the original code for the response
            code,
        })),
    )
}