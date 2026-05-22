use owo_colors::OwoColorize;
use rocket::http::{ContentType, Status};
use rocket::request::{FromRequest, Outcome};
use rocket::serde::json::{json, Json, Value};
use rocket::{catch, catchers, delete, get, launch, post, routes, Request, State};
use rocket_client_addr::ClientAddr;
use serde::Deserialize;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::time::SystemTime;
use uuid::Uuid;

mod cli;
mod limit;
mod tag;
use limit::UsageTracker;
use tag::Tagged;
mod fake;
mod filter;
mod rooms;
use rooms::{Member, Room, Rooms};

mod models;
mod auth;
mod web;
use web::{WebState, RoomsStorage};

type Storage = Arc<RwLock<Rooms>>;

#[derive(Deserialize)]
pub struct Config {
    port: u16,
    timeout_seconds: u64,
    lobby_timeout_seconds: Option<u64>,
    user_limits: HashMap<IpAddr, u16>,
    default_limit: Option<u16>,
    #[serde(default = "default_max_username_length")]
    max_username_length: usize,
    #[serde(default = "default_max_roomname_length")]
    max_roomname_length: usize,
    #[serde(default = "default_max_password_length")]
    max_password_length: usize,
    #[serde(default = "default_max_description_length")]
    max_description_length: usize,
    #[serde(default = "default_max_game_name_length")]
    max_game_name_length: usize,
}

fn default_max_username_length() -> usize { 12 }
fn default_max_roomname_length() -> usize { 20 }
fn default_max_password_length() -> usize { 32 }
fn default_max_description_length() -> usize { 100 }
fn default_max_game_name_length() -> usize { 40 }

#[launch]
fn rocket() -> _ {
    let config: Config = {
        let file = std::fs::File::open("config.ron").unwrap();
        ron::de::from_reader(file).unwrap()
    };
    let timeout_seconds = config.timeout_seconds;

    let default_limit = config.default_limit.unwrap_or(50);
    let roomref: RoomsStorage = Arc::new(RwLock::new(Rooms::new(config.user_limits, default_limit)));

    let web_state = WebState::new(
        config.max_username_length,
        config.max_roomname_length,
        config.max_password_length,
        config.max_description_length,
        config.max_game_name_length,
    );

    // Periodically remove rooms that haven't refreshed themselves
    let rr = roomref.clone();
    let lobby_timeout = Duration::from_secs(config.lobby_timeout_seconds.unwrap_or(timeout_seconds));
    std::thread::spawn(move || loop {
        let sleep_duration = Duration::from_secs(timeout_seconds);
        std::thread::sleep(sleep_duration);

        if let Ok(mut rooms) = rr.write() {
            rooms.remove_timed_out_lobbies(lobby_timeout);
        }
    });

    // Command-line interface
    let rr = roomref.clone();
    std::thread::spawn(move || cli::listener(rr));

    rocket::build()
        .configure(rocket::Config::figment().merge(("port", config.port)))
        .manage(roomref)
        .manage(web_state)
        .mount(
            "/",
            routes![
                // Lobby routes
                get_lobbies,
                register_lobby,
                update_lobby,
                delete_lobby,
                // Profile routes
                get_profile,
                post_profile,
                // Telemetry
                silence_telemetry,
                silence_jst_empty_post,
                // JWT routes (real implementation)
                web::jwt_internal,
                web::jwt_external,
                web::get_public_key,
                // User routes
                web::get_current_user,
                web::register_user,
                web::login_web,
                web::logout_user,
                web::regenerate_token,
                // Info routes
                web::get_limits,
                // Admin routes
                web::get_users,
                web::ban_user,
                web::admin_regenerate_token,
                web::get_ban_words,
                web::add_ban_word,
                web::remove_ban_word,
                web::get_sessions,
                web::revoke_session,
                web::delete_room_admin,
                web::update_room_admin,
            ],
        )
        .register("/", catchers![not_found])
}

#[catch(404)]
fn not_found() -> (ContentType, Status) {
    (ContentType::Plain, Status::NotFound)
}

#[post("/profile", data = "<body>")]
fn post_profile(body: String) -> Value {
    println!("{body}");
    json!({})
}

// Client refuses to allow a token if it hasn't been verified.
#[get("/profile")]
fn get_profile() -> Value {
    json!({})
}

#[get("/lobby")]
fn get_lobbies(shared: &State<Storage>) -> Value {
    let rooms = shared.read().unwrap();
    json!({ "rooms":  serde_json::to_value(&*rooms).unwrap()})
}

// The clients don't support HTTP redirects, so if I need to proxy incoming connections I need to
// do it through a reverse proxy.
//
// But by using a reverse proxy, the client IP address will be of that of the proxy. This lets the
// proxy attach the real originating IP as a header without having to inspect the JSON body.
struct LdnOrigin(Option<IpAddr>);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for LdnOrigin {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let header = LdnOrigin(request.headers().get_one("Ldn-Origin").and_then(|str| {
            match str.parse::<IpAddr>() {
                Ok(ip) => Some(ip),
                Err(err) => {
                    eprintln!("invalid ip from reroute: {err}");
                    None
                }
            }
        }));

        Outcome::Success(header)
    }
}

// Set up a new lobby and return it's ID.
//
// Servers may then use this ID to authorize updates for that lobby.
#[post("/lobby", data = "<body>")]
fn register_lobby(
    ldn_origin: Option<LdnOrigin>,
    remote_addr: &ClientAddr,
    body: Json<Room>,
    shared: &State<Storage>,
) -> Result<Json<Room>, Status> {
    let mut room = body.into_inner();
    let mut info = shared.write().unwrap();

    let mut ldn_origin_ip = remote_addr.ip;
    if let Some(LdnOrigin(Some(ip))) = ldn_origin {
        println!("rerouting {} -> {ldn_origin_ip}", remote_addr.ip);
        ldn_origin_ip = ip;
    }

    info.usage.increase(ldn_origin_ip).map_err(|_| {
        println!("\"{}\" was blocked by usage limits", &room.name);
        Status::TooManyRequests
    })?;

    // Remove existing room with the same name before registering
    let existing_uuids: Vec<Uuid> = info
        .rooms
        .iter()
        .filter(|(_, r)| r.value.name == room.name)
        .map(|(uuid, _)| *uuid)
        .collect();

    for uuid in existing_uuids {
        if let Some(removed) = info.rooms.remove(&uuid) {
            info.usage.decrease(&removed.real_ip);
            println!("{} \"{}\"", "Overwriting".yellow(), &room.name);
        }
    }

    println!("{} \"{}\"", "Registering".green(), &room.name);

    let uuid = Uuid::new_v4();

    if room.address.is_none() {
        room.address = Some(ldn_origin_ip);
    }

    if info
        .rooms
        .insert(uuid, Tagged::now(room.clone(), ldn_origin_ip))
        .is_some()
    {
        eprintln!("UUID conflict");
        return Err(Status::InternalServerError);
    };

    room.externalGuid = uuid.to_string();
    room.id = uuid.to_string();

    Ok(Json(room))
}

#[derive(Deserialize)]
struct LobbyUpdate {
    players: Vec<Member>,
}

// Update a lobby's information and reset the timeout timestamp
#[post("/lobby/<id>", data = "<body>")]
fn update_lobby(
    id: &str,
    body: Json<LobbyUpdate>,
    shared: &State<Storage>,
) -> (ContentType, Status) {
    let uuid = Uuid::parse_str(&id).unwrap();

    let mut info = shared.write().unwrap();

    let Some(room) = info.rooms.get_mut(&uuid) else {
        return (ContentType::JSON, Status::NotFound);
    };

    room.time = SystemTime::now();
    room.value.players = body.into_inner().players;

    (ContentType::JSON, Status::Ok)
}

#[delete("/lobby/<id>")]
fn delete_lobby(id: String, shared: &State<Storage>) {
    let uuid = Uuid::parse_str(&id).unwrap();
    let mut info = shared.write().unwrap();

    if let Some(room) = info.rooms.remove(&uuid) {
        info.usage.decrease(&room.real_ip);
    }
}

#[post("/jwt/external", data = "<body>")]
fn silence_jst_empty_post(body: Vec<u8>) -> (ContentType, &'static str) {
    let _ = body;
    (ContentType::Plain, "")
}

#[post("/telemetry")]
fn silence_telemetry() -> (ContentType, &'static str) {
    (ContentType::Plain, "")
}
