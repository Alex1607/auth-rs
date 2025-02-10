mod db;
mod models;
mod routes;
mod auth;

use std::{collections::HashMap, env};

use auth::mfa::MfaHandler;
use db::AuthRsDatabase;
use dotenv::dotenv;
use models::{role::Role, user::User};
use mongodb::bson::Uuid;
use rocket::{fairing::AdHoc, http::Method::{Connect, Delete, Get, Patch, Post, Put}, launch, routes, tokio::sync::Mutex};
use rocket_cors::{AllowedHeaders, AllowedOrigins, CorsOptions};
use rocket_db_pools::{mongodb::Collection, Database};
use routes::oauth::token::TokenOAuthData;

// oauth codes stored in memory
lazy_static::lazy_static! {
    static ref OAUTH_CODES: Mutex<HashMap<u32, TokenOAuthData>> = Mutex::new(HashMap::new());
    static ref MFA_SESSIONS: Mutex<HashMap<Uuid, MfaHandler>> = Mutex::new(HashMap::new());

    static ref ADMIN_ROLE_ID: Uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
    static ref DEFAULT_ROLE_ID: Uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    static ref SYSTEM_USER_ID: Uuid = Uuid::parse_str("00000000-0000-0000-0000-000000000000").unwrap();
}

#[launch]
fn rocket() -> _ {
    dotenv().ok();
    let cors = CorsOptions::default()
        .allowed_origins(AllowedOrigins::all())
        .allowed_methods(
            vec![Get, Post, Put, Patch, Delete, Connect]
                .into_iter()
                .map(From::from)
                .collect(),
        )
        .allowed_headers(AllowedHeaders::all())
        .allow_credentials(true);

    rocket::build()
        .attach(db::AuthRsDatabase::init())
        .attach(cors.to_cors().unwrap())
        .attach(AdHoc::try_on_ignite("Default Values", |rocket| async {
            let db = match AuthRsDatabase::fetch(&rocket) {
                Some(db) => db,
                None => return Err(rocket),
            };

            let data_db = db.database(&db::get_main_db_name());
    
            let roles_collection: Collection<Role> = data_db.collection(Role::COLLECTION_NAME);
            let users_collection: Collection<User> = data_db.collection(User::COLLECTION_NAME);

            if roles_collection.count_documents(None, None).await.unwrap() == 0 {
                let roles = vec![
                    Role::new_system(*ADMIN_ROLE_ID, "Admin".to_string()).unwrap(),
                    Role::new_system(*DEFAULT_ROLE_ID, "Default".to_string()).unwrap(),
                ];

                match roles_collection.insert_many(roles, None).await {
                    Ok(_) => println!("Inserted default roles into the database"),
                    Err(err) => {
                        eprintln!("Failed to insert default roles into the database: {:?}", err);
                        return Err(rocket)
                    },
                }
            }

            if users_collection.count_documents(None, None).await.unwrap() == 0 {
                let system_email = match env::var("SYSTEM_EMAIL") {
                    Ok(email) => email,
                    Err(_) => {
                        eprintln!("SYSTEM_EMAIL environment variable not set");
                        return Err(rocket)
                    },
                };
                let system_password = match env::var("SYSTEM_PASSWORD") {
                    Ok(password) => password,
                    Err(_) => {
                        eprintln!("SYSTEM_PASSWORD environment variable not set");
                        return Err(rocket)
                    },
                };

                let system_user = User::new_system(
                    *SYSTEM_USER_ID,
                    system_email,
                    system_password,
                    "System".to_string(),
                    "".to_string(),
                    Vec::from([(*ADMIN_ROLE_ID).to_string(), (*DEFAULT_ROLE_ID).to_string()]),
                ).unwrap();

                match users_collection.insert_one(system_user, None).await {
                    Ok(_) => println!("Inserted system user into the database"),
                    Err(err) => {
                        eprintln!("Failed to insert default users into the database: {:?}", err);
                        return Err(rocket)
                    },
                }
            }

            return Ok(rocket);
        }))
        .mount(
            "/api",
            routes![
                routes::base::base,

                // Audit Log routes
                routes::audit_logs::get_by_type::get_audit_logs_by_type,
                routes::audit_logs::get_by_id::get_audit_log_by_id,
                routes::audit_logs::get_by_entity_id::get_audit_log_by_entity_id,
                routes::audit_logs::get_by_user_id::get_audit_logs_by_user_id,

                // User Routes
                routes::users::create::create_user,
                routes::users::get_all::get_all_users,
                routes::users::get_by_id::get_user_by_id,
                routes::users::me::get_current_user,
                // this is mainly used for oauth apps
                routes::users::me::get_current_user_plain,
                routes::users::mfa::enable_totp_mfa,
                routes::users::mfa::disable_totp_mfa,
                routes::users::update::update_user,
                routes::users::delete::delete_user,

                // Role Routes
                routes::roles::create::create_role,
                routes::roles::get_all::get_all_roles,
                routes::roles::get_by_id::get_role_by_id,
                routes::roles::update::update_role,
                routes::roles::delete::delete_role,

                // OAuth Application Routes
                routes::oauth_applications::create::create_oauth_application,
                routes::oauth_applications::get_all::get_all_oauth_applications,
                routes::oauth_applications::get_by_id::get_oauth_application_by_id,
                routes::oauth_applications::update::update_oauth_application,
                routes::oauth_applications::delete::delete_oauth_application,

                // OAuth Routes
                routes::oauth::token::get_oauth_token,
                routes::oauth::authorize::authorize_oauth_application,
                routes::oauth::revoke::revoke_oauth_token,

                // Connection Routes
                routes::connections::get_by_user_id::get_by_user_id,
                routes::connections::disconnect::disconnect,

                // Auth Routes
                routes::auth::register::register,
                routes::auth::login::login,
                routes::auth::mfa::mfa
            ],
        )
}
