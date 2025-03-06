use rocket::{error, post, serde::{json::Json, Deserialize}};
use rocket_db_pools::Connection;

use crate::{auth::auth::AuthEntity, db::AuthRsDatabase, models::{audit_log::{AuditLog, AuditLogAction, AuditLogEntityType}, http_response::HttpResponse, role::Role}};

#[derive(Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct CreateRoleData {
    name: String
}

#[allow(unused)]
#[post("/roles", format = "json", data = "<data>")] 
pub async fn create_role(db: Connection<AuthRsDatabase>, req_entity: AuthEntity, data: Json<CreateRoleData>) -> Json<HttpResponse<Role>> { 
    let data = data.into_inner();

    if !req_entity.is_user() {
        return Json(HttpResponse {
            status: 403,
            message: "Forbidden".to_string(),
            data: None
        });
    }

    if !req_entity.user.unwrap().is_admin() {
        return Json(HttpResponse {
            status: 403,
            message: "Missing permissions!".to_string(),
            data: None
        });
    }

    if Role::get_by_name(&data.name, &db).await.is_ok() {
        return Json(HttpResponse {
            status: 400,
            message: "Role with that name already exists".to_string(),
            data: None
        });
    }

    let role = match Role::new(data.name) {
        Ok(role) => role,
        Err(err) => return Json(err)
    };
    
    match role.insert(&db).await {
        Ok(role) => {
            match AuditLog::new(role.id, AuditLogEntityType::Role, AuditLogAction::Create, "Role created.".to_string(), req_entity.user_id, None, None).insert(&db).await {
                Ok(_) => (),
                Err(err) => error!("{}", err)
            }
            
            Json(HttpResponse {
                status: 201,
                message: "Role created".to_string(),
                data: Some(role)
            })
        },
        Err(err) => Json(err)
    }
}