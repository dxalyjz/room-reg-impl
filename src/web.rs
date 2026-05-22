use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono;
use regex::Regex;
use rocket::http::{ContentType, Status};
use rocket::request::{FromRequest, Request};
use rocket::serde::json::{json, Json, Value};
use rocket::{delete, get, post, put, State};
use uuid::Uuid;

use crate::auth::{create_jwt, AuthKeys};
use crate::models::{BanList, Claims, ServerLimits, Session, User};
use crate::rooms::Rooms;

pub type RoomsStorage = Arc<RwLock<Rooms>>;

pub struct WebState {
    pub users: RwLock<HashMap<String, User>>,
    pub sessions: RwLock<HashMap<String, Session>>,
    pub ban_words: RwLock<BanList>,
    pub auth_keys: AuthKeys,
    pub max_username_length: usize,
    pub max_roomname_length: usize,
    pub max_password_length: usize,
    pub max_description_length: usize,
    pub max_game_name_length: usize,
}

const USERS_FILE: &str = "users.json";
const SESSIONS_FILE: &str = "sessions.json";
const BANWORDS_FILE: &str = "banwords.json";

fn load_users() -> HashMap<String, User> {
    if let Ok(file) = std::fs::File::open(USERS_FILE) {
        if let Ok(users) = serde_json::from_reader(file) {
            return users;
        }
    }
    HashMap::new()
}

fn load_sessions() -> HashMap<String, Session> {
    if let Ok(file) = std::fs::File::open(SESSIONS_FILE) {
        if let Ok(s) = serde_json::from_reader(file) {
            return s;
        }
    }
    HashMap::new()
}

fn load_ban_words() -> BanList {
    if let Ok(file) = std::fs::File::open(BANWORDS_FILE) {
        if let Ok(s) = serde_json::from_reader(file) {
            return s;
        }
    }
    BanList::default()
}

fn save_users(users: &HashMap<String, User>) {
    if let Ok(file) = std::fs::File::create(USERS_FILE) {
        let _ = serde_json::to_writer_pretty(file, users);
    }
}

fn save_sessions(sessions: &HashMap<String, Session>) {
    if let Ok(file) = std::fs::File::create(SESSIONS_FILE) {
        let _ = serde_json::to_writer_pretty(file, sessions);
    }
}

fn save_ban_words(words: &BanList) {
    if let Ok(file) = std::fs::File::create(BANWORDS_FILE) {
        let _ = serde_json::to_writer_pretty(file, words);
    }
}

pub struct Headers {
    pub session_token: Option<String>,
    pub username: Option<String>,
    pub token: Option<String>,
    pub authorization: Option<String>,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Headers {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> rocket::outcome::Outcome<Self, (Status, Self::Error), Status> {
        rocket::outcome::Outcome::Success(Headers {
            session_token: request.headers().get("x-session-token").next().map(|s| s.to_string()),
            username: request.headers().get("x-username").next().map(|s| s.to_string()),
            token: request.headers().get("x-token").next().map(|s| s.to_string()),
            authorization: request.headers().get("Authorization").next().map(|s| s.to_string()),
        })
    }
}

fn check_admin(state: &WebState, headers: &Headers) -> Result<(), (Status, &'static str)> {
    let token = match &headers.session_token {
        Some(t) => t.as_str(),
        None => return Err((Status::Forbidden, "Admin Access Required")),
    };

    let sessions = state.sessions.read().unwrap();
    let session = match sessions.get(token) {
        Some(s) => s,
        None => return Err((Status::Forbidden, "Admin Access Required")),
    };

    if chrono::Utc::now().timestamp() > session.expires_at {
        return Err((Status::Unauthorized, "Session Expired"));
    }

    let users = state.users.read().unwrap();
    match users.get(&session.username) {
        Some(user) if user.roles.contains(&"admin".to_string()) => Ok(()),
        _ => Err((Status::Forbidden, "Admin Access Required")),
    }
}

#[get("/users/me")]
pub fn get_current_user(
    state: &State<WebState>,
    headers: Headers,
) -> (Status, Option<Json<User>>) {
    let token = match headers.session_token {
        Some(ref t) => t.clone(),
        None => return (Status::Unauthorized, None),
    };

    let sessions = state.sessions.read().unwrap();
    let session = match sessions.get(&token) {
        Some(s) => s,
        None => return (Status::Unauthorized, None),
    };

    if chrono::Utc::now().timestamp() <= session.expires_at {
        let users = state.users.read().unwrap();
        if let Some(user) = users.get(&session.username) {
            return (Status::Ok, Some(Json(user.clone())));
        }
    }
    (Status::Unauthorized, None)
}

#[post("/users/register", data = "<body>")]
pub fn register_user(
    state: &State<WebState>,
    body: String,
) -> (Status, Value) {
    let payload: User = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return (Status::BadRequest, json!({"error": "Invalid JSON"})),
    };

    if payload.password_hash.len() > state.max_password_length {
        return (
            Status::BadRequest,
            json!({"error": format!("Password too long (max {} chars)", state.max_password_length)}),
        );
    }

    let pattern = format!(r"^[a-zA-Z0-9_\-\.]{{1,{}}}$", state.max_username_length);
    let re = Regex::new(&pattern).unwrap();
    if !re.is_match(&payload.username) {
        return (
            Status::BadRequest,
            json!({"error": format!("Invalid Username. Allowed: a-z, 0-9, _, -, . (Max {} chars). No spaces or other symbols allowed.", state.max_username_length)}),
        );
    }

    {
        let ban_words = state.ban_words.read().unwrap();
        for word in &ban_words.words {
            let mut is_match = false;
            if let Ok(re_word) = Regex::new(word) {
                if re_word.is_match(&payload.username) {
                    is_match = true;
                }
            } else {
                let clean_word = word.trim_matches('*');
                if word.starts_with('*') && word.ends_with('*') {
                    if payload.username.contains(clean_word) {
                        is_match = true;
                    }
                } else if payload.username == *word {
                    is_match = true;
                }
            }
            if is_match {
                return (
                    Status::BadRequest,
                    json!({"error": "Username contains a forbidden word. Do not attempt to bypass this restriction."}),
                );
            }
        }
    }

    {
        let mut users = state.users.write().unwrap();
        if users.contains_key(&payload.username) {
            return (Status::Conflict, json!({"error": "User exists"}));
        }

        let yuzu_token = Uuid::new_v4().to_string();
        let hash = match bcrypt::hash(&payload.password_hash, bcrypt::DEFAULT_COST) {
            Ok(h) => h,
            Err(_) => return (Status::InternalServerError, json!({"error": "Password Hash Failed"})),
        };

        users.insert(
            payload.username.clone(),
            User {
                username: payload.username.clone(),
                password_hash: hash,
                yuzu_token,
                avatar_url: payload.avatar_url.clone(),
                roles: vec![],
                is_banned: false,
                ban_reason: None,
            },
        );
    }

    let users = state.users.read().unwrap();
    save_users(&users);
    (Status::Ok, json!(payload))
}

#[post("/users/login", data = "<body>")]
pub fn login_web(
    state: &State<WebState>,
    body: String,
) -> (Status, Value) {
    let payload: User = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return (Status::BadRequest, json!({"error": "Invalid JSON"})),
    };

    let users = state.users.read().unwrap();
    let user = match users.get(&payload.username) {
        Some(u) => u,
        None => return (Status::Unauthorized, json!({"error": "Invalid Credentials"})),
    };

    if !bcrypt::verify(&payload.password_hash, &user.password_hash).unwrap_or(false) {
        return (Status::Unauthorized, json!({"error": "Invalid Credentials"}));
    }

    if user.is_banned {
        let reason = user.ban_reason.clone().unwrap_or("No reason provided".to_string());
        return (
            Status::Forbidden,
            json!({"error": "This user is banned", "reason": reason}),
        );
    }

    let session_id = Uuid::new_v4().to_string();
    let expires_at = chrono::Utc::now().timestamp() + 3600;

    let session = Session {
        id: session_id.clone(),
        username: user.username.clone(),
        expires_at,
    };

    {
        let mut sessions = state.sessions.write().unwrap();
        sessions.insert(session_id.clone(), session);
    }
    let sessions = state.sessions.read().unwrap();
    save_sessions(&sessions);

    let mut response_json = serde_json::to_value(user.clone()).unwrap();
    response_json
        .as_object_mut()
        .unwrap()
        .insert("session_id".to_string(), serde_json::Value::String(session_id));

    (Status::Ok, json!(response_json))
}

#[post("/users/logout")]
pub fn logout_user(
    state: &State<WebState>,
    headers: Headers,
) -> (Status, &'static str) {
    if let Some(ref token) = headers.session_token {
        let mut sessions = state.sessions.write().unwrap();
        sessions.remove(token.as_str());
        drop(sessions);
        let sessions = state.sessions.read().unwrap();
        save_sessions(&sessions);
    }
    (Status::Ok, "Logged out")
}

#[post("/users/regenerate_token", data = "<body>")]
pub fn regenerate_token(
    state: &State<WebState>,
    headers: Headers,
    body: String,
) -> (Status, Value) {
    let payload: serde_json::Value = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return (Status::BadRequest, json!({"error": "Invalid JSON"})),
    };

    let password = match payload.get("password").and_then(|p| p.as_str()) {
        Some(p) => p,
        None => return (Status::BadRequest, json!({"error": "Password required"})),
    };

    let session_id = match headers.session_token {
        Some(ref id) => id.clone(),
        None => return (Status::Unauthorized, json!({"error": "Not logged in"})),
    };

    let username = {
        let sessions = state.sessions.read().unwrap();
        match sessions.get(&session_id) {
            Some(session) => session.username.clone(),
            None => return (Status::Unauthorized, json!({"error": "Invalid session"})),
        }
    };

    {
        let users = state.users.read().unwrap();
        match users.get(&username) {
            Some(user) => {
                if !bcrypt::verify(password, &user.password_hash).unwrap_or(false) {
                    return (Status::Unauthorized, json!({"error": "Invalid password"}));
                }
            }
            None => return (Status::NotFound, json!({"error": "User not found"})),
        }
    }

    let new_token = Uuid::new_v4().to_string();
    {
        let mut users = state.users.write().unwrap();
        if let Some(user) = users.get_mut(&username) {
            user.yuzu_token = new_token.clone();
        } else {
            return (Status::NotFound, json!({"error": "User not found"}));
        }
    }
    let users = state.users.read().unwrap();
    save_users(&users);

    (
        Status::Ok,
        json!({"success": true, "yuzu_token": new_token}),
    )
}

#[get("/info/limits")]
pub fn get_limits(state: &State<WebState>) -> Json<ServerLimits> {
    Json(ServerLimits {
        max_username_length: state.max_username_length,
        max_roomname_length: state.max_roomname_length,
        max_password_length: state.max_password_length,
        max_description_length: state.max_description_length,
        max_game_name_length: state.max_game_name_length,
    })
}

#[get("/users")]
pub fn get_users(
    state: &State<WebState>,
    headers: Headers,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }
    let users = state.users.read().unwrap();
    (Status::Ok, json!(*users))
}

#[post("/admin/ban", data = "<body>")]
pub fn ban_user(
    state: &State<WebState>,
    headers: Headers,
    body: String,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }

    let payload: serde_json::Value = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return (Status::BadRequest, json!({"error": "Invalid JSON"})),
    };

    let target = match payload.get("username").and_then(|v| v.as_str()) {
        Some(u) => u,
        None => return (Status::BadRequest, json!({"error": "Missing username"})),
    };

    let ban = payload.get("banned").and_then(|v| v.as_bool()).unwrap_or(true);
    let reason = payload.get("reason").and_then(|v| v.as_str()).map(|s| s.to_string());

    {
        let mut users = state.users.write().unwrap();
        if let Some(user) = users.get_mut(target) {
            user.is_banned = ban;
            user.ban_reason = if ban { reason } else { None };
        } else {
            return (Status::BadRequest, json!({"error": "User not found"}));
        }
    }
    let users = state.users.read().unwrap();
    save_users(&users);

    if ban {
        let mut sessions = state.sessions.write().unwrap();
        sessions.retain(|_, s| s.username != target);
        drop(sessions);
        let sessions = state.sessions.read().unwrap();
        save_sessions(&sessions);
    }

    (Status::Ok, json!({"success": true}))
}

#[post("/admin/regenerate_token/<username>")]
pub fn admin_regenerate_token(
    username: &str,
    state: &State<WebState>,
    headers: Headers,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }

    let new_token = Uuid::new_v4().to_string();
    {
        let mut users = state.users.write().unwrap();
        if let Some(user) = users.get_mut(username) {
            user.yuzu_token = new_token.clone();
        } else {
            return (Status::NotFound, json!({"error": "User not found"}));
        }
    }
    let users = state.users.read().unwrap();
    save_users(&users);

    (
        Status::Ok,
        json!({"success": true, "username": username, "yuzu_token": new_token}),
    )
}

#[get("/admin/banwords")]
pub fn get_ban_words(
    state: &State<WebState>,
    headers: Headers,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }
    let words = state.ban_words.read().unwrap();
    (Status::Ok, json!(*words))
}

#[post("/admin/banwords", data = "<body>")]
pub fn add_ban_word(
    state: &State<WebState>,
    headers: Headers,
    body: String,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }

    let payload: serde_json::Value = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return (Status::BadRequest, json!({"error": "Invalid JSON"})),
    };

    if let Some(word) = payload.get("word").and_then(|v| v.as_str()) {
        let mut list = state.ban_words.write().unwrap();
        if !list.words.contains(&word.to_string()) {
            list.words.push(word.to_string());
            drop(list);
            let words = state.ban_words.read().unwrap();
            save_ban_words(&words);
        }
        (Status::Ok, json!({"success": true}))
    } else {
        (Status::BadRequest, json!({"error": "Missing word"}))
    }
}

#[delete("/admin/banwords", data = "<body>")]
pub fn remove_ban_word(
    state: &State<WebState>,
    headers: Headers,
    body: String,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }

    let payload: serde_json::Value = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return (Status::BadRequest, json!({"error": "Invalid JSON"})),
    };

    if let Some(word) = payload.get("word").and_then(|v| v.as_str()) {
        let mut list = state.ban_words.write().unwrap();
        list.words.retain(|w| w != word);
        drop(list);
        let words = state.ban_words.read().unwrap();
        save_ban_words(&words);
        (Status::Ok, json!({"success": true}))
    } else {
        (Status::BadRequest, json!({"error": "Missing word"}))
    }
}

#[get("/admin/sessions")]
pub fn get_sessions(
    state: &State<WebState>,
    headers: Headers,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }
    let sessions = state.sessions.read().unwrap();
    (Status::Ok, json!(*sessions))
}

#[delete("/admin/sessions/<id>")]
pub fn revoke_session(
    id: &str,
    state: &State<WebState>,
    headers: Headers,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }

    let mut sessions = state.sessions.write().unwrap();
    if sessions.remove(id).is_some() {
        drop(sessions);
        let sessions = state.sessions.read().unwrap();
        save_sessions(&sessions);
        (Status::Ok, json!({"success": true}))
    } else {
        (Status::NotFound, json!({"error": "Session not found"}))
    }
}

#[delete("/admin/rooms/<id>")]
pub fn delete_room_admin(
    id: &str,
    state: &State<WebState>,
    room_state: &State<RoomsStorage>,
    headers: Headers,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }

    let uuid = match uuid::Uuid::parse_str(id) {
        Ok(u) => u,
        Err(_) => return (Status::BadRequest, json!({"error": "Invalid ID"})),
    };

    let mut rooms = room_state.write().unwrap();
    if rooms.remove(&uuid).is_some() {
        (Status::Ok, json!({"success": true}))
    } else {
        (Status::NotFound, json!({"error": "Room not found"}))
    }
}

#[put("/admin/rooms/<id>", data = "<body>")]
pub fn update_room_admin(
    id: &str,
    state: &State<WebState>,
    room_state: &State<RoomsStorage>,
    headers: Headers,
    body: String,
) -> (Status, Value) {
    if let Err(e) = check_admin(state, &headers) {
        return (e.0, json!({"error": e.1}));
    }

    let payload: serde_json::Value = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(_) => return (Status::BadRequest, json!({"error": "Invalid JSON"})),
    };

    let uuid = match uuid::Uuid::parse_str(id) {
        Ok(u) => u,
        Err(_) => return (Status::BadRequest, json!({"error": "Invalid ID"})),
    };

    let mut rooms = room_state.write().unwrap();
    if let Some(room) = rooms.rooms.get_mut(&uuid) {
        if let Some(name) = payload.get("name").and_then(|v| v.as_str()) {
            room.value.name = name.to_string();
        }
        if let Some(desc) = payload.get("description").and_then(|v| v.as_str()) {
            room.value.description = desc.to_string();
        }
        (Status::Ok, json!(room.value.clone()))
    } else {
        (Status::NotFound, json!({"error": "Room not found"}))
    }
}

#[post("/jwt/internal", data = "<body>")]
pub fn jwt_internal(
    state: &State<WebState>,
    headers: Headers,
    body: String,
) -> (Status, (ContentType, String)) {
    let _ = body;
    let username = headers.username.as_deref();
    let token = headers.token.as_deref();

    if let (Some(u), Some(t)) = (username, token) {
        let users = state.users.read().unwrap();
        if let Some(user) = users.get(u) {
            if user.is_banned {
                return (
                    Status::Forbidden,
                    (ContentType::Plain, "User is banned".to_string()),
                );
            }
            if user.yuzu_token == t {
                match create_jwt(user, "citra-core", &state.auth_keys) {
                    Ok(jwt) => {
                        return (Status::Ok, (ContentType::HTML, jwt));
                    }
                    Err(_) => {
                        return (
                            Status::InternalServerError,
                            (ContentType::Plain, "JWT Gen Failed".to_string()),
                        );
                    }
                }
            }
        }
    }
    (
        Status::Unauthorized,
        (ContentType::Plain, "Invalid Credentials".to_string()),
    )
}

#[post("/jwt/external/<audience>", data = "<body>")]
pub fn jwt_external(
    audience: &str,
    state: &State<WebState>,
    headers: Headers,
    body: String,
) -> (Status, (ContentType, String)) {
    let _ = body;
    let user_opt = {
        if let Some(jwt_str) = headers.authorization.as_deref().and_then(|s| s.strip_prefix("Bearer ")) {
            let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(
                state.auth_keys.public_key_pem.as_bytes(),
            )
            .unwrap();

            let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
            validation.validate_aud = false;
            validation.set_audience(&["citra-core"]);

            if let Ok(token_data) =
                jsonwebtoken::decode::<Claims>(jwt_str, &decoding_key, &validation)
            {
                Some(token_data.claims.username)
            } else {
                None
            }
        } else {
            let username = headers.username.as_deref();
            let token = headers.token.as_deref();
            if let (Some(u), Some(t)) = (username, token) {
                let users = state.users.read().unwrap();
                if let Some(user) = users.get(u) {
                    if user.yuzu_token == t {
                        Some(u.to_string())
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        }
    };

    if let Some(username) = user_opt {
        let users = state.users.read().unwrap();
        if let Some(user) = users.get(&username) {
            if user.is_banned {
                return (
                    Status::Forbidden,
                    (ContentType::Plain, "User is banned".to_string()),
                );
            }
            match create_jwt(user, audience, &state.auth_keys) {
                Ok(jwt) => {
                    return (Status::Ok, (ContentType::HTML, jwt));
                }
                Err(_) => {
                    return (
                        Status::InternalServerError,
                        (ContentType::Plain, "JWT Gen Failed".to_string()),
                    );
                }
            }
        }
    }
    (
        Status::Unauthorized,
        (ContentType::Plain, String::new()),
    )
}

#[get("/jwt/external/key.pem")]
pub fn get_public_key(state: &State<WebState>) -> (Status, (ContentType, String)) {
    (
        Status::Ok,
        (ContentType::Plain, state.auth_keys.public_key_pem.clone()),
    )
}

impl WebState {
    pub fn new(
        max_username_length: usize,
        max_roomname_length: usize,
        max_password_length: usize,
        max_description_length: usize,
        max_game_name_length: usize,
    ) -> Self {
        let mut users = load_users();
        if !users.contains_key("suyu") {
            users.insert(
                "suyu".to_string(),
                User {
                    username: "suyu".to_string(),
                    password_hash: "password".to_string(),
                    yuzu_token: "sutoken".to_string(),
                    avatar_url: "".to_string(),
                    roles: vec![],
                    is_banned: false,
                    ban_reason: None,
                },
            );
            save_users(&users);
        }

        WebState {
            users: RwLock::new(users),
            sessions: RwLock::new(load_sessions()),
            ban_words: RwLock::new(load_ban_words()),
            auth_keys: AuthKeys::new(),
            max_username_length,
            max_roomname_length,
            max_password_length,
            max_description_length,
            max_game_name_length,
        }
    }
}
