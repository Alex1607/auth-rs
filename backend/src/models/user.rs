use anyhow::Result;
use mongodb::bson::{doc, DateTime, Uuid};
use pwhash::bcrypt;
use rand::Rng;
use rocket_db_pools::{mongodb::{Collection, Database}, Connection};
use rocket::{futures::StreamExt, serde::{Deserialize, Serialize}};
use crate::{db::{get_main_db, AuthRsDatabase}, ADMIN_ROLE_ID, DEFAULT_ROLE_ID, SYSTEM_USER_ID};

use super::http_response::HttpResponse;

#[derive(Debug, Clone, Serialize, Deserialize)] 
#[serde(crate = "rocket::serde")]
#[serde(rename_all = "camelCase")]
pub struct User {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub password_hash: String,
    pub totp_secret: Option<String>,
    pub token: String,
    pub roles: Vec<Uuid>,
    pub disabled: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)] 
#[serde(crate = "rocket::serde")] 
#[serde(rename_all = "camelCase")] 
pub struct UserMinimal {
    #[serde(rename = "_id")]
    pub id: Uuid,
    pub email: String,
    pub first_name: String,
    pub last_name: String,
    pub roles: Vec<Uuid>,
    pub mfa: bool,
    pub disabled: bool,
    pub created_at: String,
}

impl UserMinimal {
    pub async  fn to_full(&self, connection: &Connection<AuthRsDatabase>) -> Result<User, HttpResponse<UserMinimal>> {
        User::get_full_by_id(self.id.clone(), connection).await
    }
}

impl User {
    pub const COLLECTION_NAME: &'static str = "users";

    pub fn generate_token() -> String {
        rand::rng().sample_iter(rand::distr::Alphanumeric).take(128).map(char::from).collect()
    }

    pub fn verify_password(&self, password: &str) -> bool {
        bcrypt::verify(password, &self.password_hash)
    }

    pub fn new(email: String, password: String, first_name: String, last_name: String) -> Result<Self, HttpResponse<UserMinimal>> {
        let password_hash = match bcrypt::hash(password) {
            Ok(hash) => hash,
            Err(err) => return Err(HttpResponse {
                status: 500,
                message: format!("Failed to hash password: {:?}", err),
                data: None
            })
        };

        Ok(Self {
            id: Uuid::new(),
            email,
            first_name,
            last_name,
            password_hash,
            totp_secret: None,
            token: Self::generate_token(),
            roles: Vec::from([(*DEFAULT_ROLE_ID)]),
            disabled: false,
            created_at: DateTime::now().to_string(),
        })
    }

    pub fn new_system(id: Uuid, email: String, password: String, first_name: String, last_name: String, roles: Vec<String>) -> Result<Self, HttpResponse<UserMinimal>> {
        let password_hash = match bcrypt::hash(password) {
            Ok(hash) => hash,
            Err(err) => return Err(HttpResponse {
                status: 500,
                message: format!("Failed to hash password: {:?}", err),
                data: None
            })
        };

        Ok(Self {
            id,
            email,
            first_name,
            last_name,
            password_hash,
            totp_secret: None,
            token: Self::generate_token(),
            roles: roles.iter().map(|role| Uuid::parse_str(role).unwrap()).collect(),
            disabled: false,
            created_at: DateTime::now().to_string(),
        })
    }

    pub fn to_minimal(&self) -> UserMinimal {
        UserMinimal {
            id: self.id.clone(),
            email: self.email.clone(),
            first_name: self.first_name.clone(),
            last_name: self.last_name.clone(),
            roles: self.roles.clone(),
            mfa: self.totp_secret.is_some(),
            disabled: self.disabled.clone(),
            created_at: self.created_at.clone()
        }
    }

    #[allow(unused)]
    pub fn is_admin(&self) -> bool {
        self.id == *SYSTEM_USER_ID || self.roles.contains(&*ADMIN_ROLE_ID)
    }

    #[allow(unused)]
    pub fn is_system_admin(&self) -> bool {
        self.id == *SYSTEM_USER_ID
    }

    // ONLY USE THIS INTERNALLY!
    #[allow(unused)]
    pub async fn get_full_by_id(id: Uuid, connection: &Connection<AuthRsDatabase>) -> Result<User, HttpResponse<UserMinimal>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await.unwrap() {
            Some(user) => Ok(user),
            None => Err(HttpResponse {
                status: 404,
                message: "User not found".to_string(),
                data: None
            })
        }
    }

    // ONLY USE THIS INTERNALLY!
    #[allow(unused)]
    pub async fn get_full_by_token(token: String, mut db: &Database) -> Result<User, HttpResponse<UserMinimal>> {
        let db = db.collection(Self::COLLECTION_NAME);

        let filter = doc! {
            "token": token
        };
        match db.find_one(filter, None).await.unwrap() {
            Some(user) => Ok(user),
            None => Err(HttpResponse {
                status: 404,
                message: "User not found".to_string(),
                data: None
            })
        }
    }

    #[allow(unused)]
    pub async fn get_by_id(id: Uuid, connection: &Connection<AuthRsDatabase>) -> Result<UserMinimal, HttpResponse<UserMinimal>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": id
        };
        match db.find_one(filter, None).await.unwrap() {
            Some(user) => Ok(user.to_minimal()),
            None => Err(HttpResponse {
                status: 404,
                message: "User not found".to_string(),
                data: None
            })
        }
    }

    #[allow(unused)]
    pub async fn get_by_email(email: &str, connection: &Connection<AuthRsDatabase>) -> Result<UserMinimal, HttpResponse<UserMinimal>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "email": email
        };
        match db.find_one(filter, None).await.unwrap() {
            Some(user) => Ok(user.to_minimal()),
            None => Err(HttpResponse {
                status: 404,
                message: "User not found".to_string(),
                data: None
            })
        }
    }

    #[allow(unused)]
    pub async fn get_all(connection: &Connection<AuthRsDatabase>) -> Result<Vec<UserMinimal>, HttpResponse<Vec<UserMinimal>>> {
        let db = Self::get_collection(connection);

        match db.find(None, None).await {
            Ok(cursor) => {
                let users = cursor.map(|doc| {
                    let user: User = doc.unwrap();
                    return user.to_minimal();
                }).collect::<Vec<UserMinimal>>().await;
                Ok(users)
            },
            Err(err) => Err(HttpResponse {
                status: 500,
                message: format!("Error fetching users: {:?}", err),
                data: None
            })
        }
    }

    #[allow(unused)]
    pub async fn insert(&self, connection: &Connection<AuthRsDatabase>) -> Result<UserMinimal, HttpResponse<UserMinimal>> {
        let db = Self::get_collection(connection);

        match db.insert_one(self.clone(), None).await {
            Ok(_) => Ok(self.clone().to_minimal()),
            Err(err) => Err(HttpResponse {
                status: 500,
                message: format!("Error inserting user: {:?}", err),
                data: None
            })
        }
    }

    #[allow(unused)]
    pub async fn update(&self, connection: &Connection<AuthRsDatabase>) -> Result<UserMinimal, HttpResponse<UserMinimal>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        match db.replace_one(filter, self.clone(), None).await {
            Ok(_) => Ok(self.clone().to_minimal()),
            Err(err) => Err(HttpResponse {
                status: 500,
                message: format!("Error updating user: {:?}", err),
                data: None
            })
        }
    }

    #[allow(unused)]
    pub async fn disable(&self, connection: &Connection<AuthRsDatabase>) -> Result<(), HttpResponse<()>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        let update = doc! {
            "$set": {
                "disabled": true
            }
        };
        match db.find_one_and_update(filter, update, None).await {
            Ok(_) => Ok(()),
            Err(err) => Err(HttpResponse {
                status: 500,
                message: format!("Error disabeling user: {:?}", err),
                data: None
            })
        }
    }

    #[allow(unused)]
    pub async fn enable(&self, connection: &Connection<AuthRsDatabase>) -> Result<(), HttpResponse<()>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        let update = doc! {
            "$set": {
                "disabled": false
            }
        };
        match db.find_one_and_update(filter, update, None).await {
            Ok(_) => Ok(()),
            Err(err) => Err(HttpResponse {
                status: 500,
                message: format!("Error enabeling user: {:?}", err),
                data: None
            })
        }
    }

    #[allow(unused)]
    pub async fn delete(&self, connection: &Connection<AuthRsDatabase>) -> Result<UserMinimal, HttpResponse<()>> {
        let db = Self::get_collection(connection);

        let filter = doc! {
            "_id": self.id
        };
        match db.delete_one(filter, None).await {
            Ok(_) => Ok(self.clone().to_minimal()),
            Err(err) => Err(HttpResponse {
                status: 500,
                message: format!("Error deleting user: {:?}", err),
                data: None
            })
        }
    }

    #[allow(unused)]
    fn get_collection(connection: &Connection<AuthRsDatabase>) -> Collection<Self> {
        let db = get_main_db(connection);
        db.collection(Self::COLLECTION_NAME)
    }
}