use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use rsa::{
    pkcs8::{EncodePublicKey, EncodePrivateKey, LineEnding},
    RsaPrivateKey,
};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::models::{Claims, User};

pub struct AuthKeys {
    pub encoding_key: EncodingKey,
    pub public_key_pem: String,
}

impl AuthKeys {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        let bits = 2048;
        let private_key =
            RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");

        let public_key = private_key.to_public_key();
        let public_key_pem = public_key
            .to_public_key_pem(LineEnding::LF)
            .expect("failed to convert to pem");

        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .expect("failed to get private key pem");

        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .expect("failed to create encoding key");

        AuthKeys {
            encoding_key,
            public_key_pem: public_key_pem.to_string(),
        }
    }
}

pub fn create_jwt(user: &User, audience: &str, keys: &AuthKeys) -> Result<String, jsonwebtoken::errors::Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let expiration = now + 60 * 60 * 24;

    let claims = Claims {
        sub: user.username.clone(),
        iss: "citra-core".to_string(),
        aud: audience.to_string(),
        exp: expiration,
        iat: now,
        jti: Uuid::new_v4().to_string(),
        username: user.username.clone(),
        display_name: user.username.clone(),
        avatar_url: user.avatar_url.clone(),
        roles: user.roles.clone(),
    };

    let header = Header::new(Algorithm::RS256);
    encode(&header, &claims, &keys.encoding_key)
}
