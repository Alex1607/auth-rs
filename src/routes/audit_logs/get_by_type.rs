use rocket::{get, serde::json::Json};
use rocket_db_pools::Connection;

use crate::{auth::auth::AuthEntity, db::AuthRsDatabase, models::{audit_log::{AuditLog, AuditLogEntityType}, http_response::HttpResponse}};


#[allow(unused)]
#[get("/audit-logs/<type>", format = "json")] 
pub async fn get_audit_logs_by_type(db: Connection<AuthRsDatabase>, req_entity: AuthEntity, r#type: &str) -> Json<HttpResponse<Vec<AuditLog>>> {
    if !req_entity.is_user() || !req_entity.user.unwrap().is_global_admin() {
        return Json(HttpResponse {
            status: 403,
            message: "Missing permissions!".to_string(),
            data: None
        });
    }

    let entity_type = match AuditLogEntityType::from_string(&r#type) {
        Ok(entity_type) => Some(entity_type),
        Err(err) => return Json(err)
    };

    match AuditLog::get_all_from_type(entity_type.unwrap(), &db).await {
        Ok(audit_logs) => Json(HttpResponse {
            status: 200,
            message: "Successfully retrieved all audit logs by type".to_string(),
            data: Some(audit_logs),
        }),
        Err(err) => Json(err)
    }
}