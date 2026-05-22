use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    #[serde(default)]
    pub yuzu_token: String,
    #[serde(default)]
    pub avatar_url: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub is_banned: bool,
    #[serde(default)]
    pub ban_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub username: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BanList {
    pub words: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iss: String,
    pub aud: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    pub username: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "avatarUrl")]
    pub avatar_url: String,
    pub roles: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct ServerLimits {
    pub max_username_length: usize,
    pub max_roomname_length: usize,
    pub max_password_length: usize,
    pub max_description_length: usize,
    pub max_game_name_length: usize,
}
