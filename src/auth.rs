use core::fmt;
use std::sync::Arc;

use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, RequestPartsExt, Router,
};
use chrono::prelude::*;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use serde_json::json;

use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};

use crate::AppState;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub enum Role {
    User,
    Admin,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "user" => Some(Role::User),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Role::User => write!(f, "user"),
            Role::Admin => write!(f, "admin"),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Claims {
    uid: String,
    role: Role,
    exp: i64,
}

pub struct Authorizer {
    keys: Keys,
    valid_duration: chrono::Duration,
}

impl Authorizer {
    pub fn new(secret: &[u8], valid_duration: i64) -> Authorizer {
        Authorizer {
            keys: Keys::new(secret),
            valid_duration: chrono::Duration::seconds(valid_duration),
        }
    }
}

async fn login_handler(
    state: State<Arc<AppState>>,
    Json(payload): Json<AuthPayload>,
) -> Result<String, AuthError> {
    // Check if the user sent the credentials
    if payload.username.is_empty() || payload.password.is_empty() {
        return Err(AuthError::NoCredentials);
    }

    // Here you can check the user credentials from a database
    if payload.username != "foo" || payload.password != "bar" {
        return Err(AuthError::NoCredentials);
    }

    let claims = Claims {
        uid: "123".to_string(),
        role: Role::Admin,
        // Mandatory expiry time as UTC timestamp
        exp: Utc::now().timestamp() + state.authorizer.valid_duration.num_seconds(),
    };

    // Create the authorization token
    let token = jsonwebtoken::encode(&Header::default(), &claims, &state.authorizer.keys.encoding)
        .map_err(|_| AuthError::TokenFailure)?;

    // Send the authorized token
    Ok(token)
}

async fn whoami_handler(claims: Claims, state: State<Arc<AppState>>) -> Result<String, AuthError> {
    // let token = token_from_header(&headers).ok_or(Error::InvalidAuthHeader)?;
    // let claims = get_claims(&state.authorizer, &token)?;
    Ok(format!("id: {}, role: {}", claims.uid, claims.role))
}

pub fn router() -> Router<Arc<AppState>> {
    Router::new()
        .route("/whoami", get(whoami_handler))
        .route("/login", post(login_handler))
}

#[derive(Debug, Deserialize)]
struct AuthPayload {
    username: String,
    password: String,
}

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

impl Keys {
    fn new(secret: &[u8]) -> Self {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

static KEYS: Lazy<Keys> = Lazy::new(|| {
    // let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
    let secret = "secret";
    Keys::new(secret.as_bytes())
});

#[async_trait]
impl<S> FromRequestParts<S> for Claims
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract the token from the authorization header
        let TypedHeader(Authorization(bearer)) = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| AuthError::InvalidAuthHeader)?;
        // Decode the user data
        let token_data =
            jsonwebtoken::decode::<Claims>(bearer.token(), &KEYS.decoding, &Validation::default())
                .map_err(|_| AuthError::InvalidToken)?;

        if token_data.claims.exp < Utc::now().timestamp() {
            return Err(AuthError::ExpiredToken);
        }

        Ok(token_data.claims)
    }
}

pub enum AuthError {
    InvalidAuthHeader,
    InvalidToken,
    ExpiredToken,
    NoCredentials,
    TokenFailure,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AuthError::InvalidAuthHeader => {
                (StatusCode::UNAUTHORIZED, "Invalid authorization header")
            }
            AuthError::InvalidToken => (StatusCode::UNAUTHORIZED, "Invalid token"),
            AuthError::ExpiredToken => (StatusCode::UNAUTHORIZED, "Token is expired"),
            AuthError::NoCredentials => (
                StatusCode::UNAUTHORIZED,
                "Incomplete or missing credentials",
            ),
            AuthError::TokenFailure => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
        };
        let body = Json(json!({ "message": error_message }));
        (status, body).into_response()
    }
}
