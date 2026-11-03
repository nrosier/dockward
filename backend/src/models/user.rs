//! The `User` object returned by the API. It never includes `password_hash`
//! (`specs/api.md`, Auth).

use serde::Serialize;

use crate::db::users::UserRow;
use crate::error::AppError;
use crate::services::time;

#[derive(Debug, Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: Option<String>,
    pub role: String,
    pub auth_provider: String,
    pub created_at: Option<String>,
}

impl TryFrom<UserRow> for User {
    type Error = AppError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        Ok(User {
            id: row.id,
            username: row.username,
            email: row.email,
            role: row.role,
            auth_provider: row.auth_provider,
            created_at: row.created_at.map(time::rfc3339).transpose()?,
        })
    }
}
