use core::fmt;
use std::sync::Arc;

use chrono::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use warp::{
    filters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, reply, Filter, Rejection, Reply,
};

use crate::error::Error;
use crate::{LoginRequest, LoginResponse, Users, WebResult};

const BEARER: &str = "Bearer ";

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
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    valid_duration: chrono::Duration,
}

impl Authorizer {
    pub fn new(secret: &[u8], valid_duration: i64) -> Authorizer {
        Authorizer {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            valid_duration: chrono::Duration::seconds(valid_duration),
        }
    }

    pub fn create_token(&self, uid: &str, role: &Role) -> Result<String, Error> {
        let expiration = Utc::now()
            .checked_add_signed(self.valid_duration)
            .expect("invalid timestamp") // safe to unwrap because it should always valid
            .timestamp();

        let claims = Claims {
            uid: uid.to_owned(),
            role: role.clone(),
            exp: expiration,
        };

        jsonwebtoken::encode(
            &Header::new(Algorithm::default()),
            &claims,
            &self.encoding_key,
        )
        .map_err(|_| Error::JwtFailure)
    }
}

pub fn must_auth(
    auth: Arc<Authorizer>,
    role: Role,
) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (role.clone(), headers))
        .and_then(move |(role, headers)| authorize(Arc::clone(&auth), (role, headers)))
}

pub fn extract_claims(
    auth: Arc<Authorizer>,
) -> impl Filter<Extract = (Claims,), Error = Rejection> + Clone {
    headers_cloned().and_then(move |headers| get_claims(Arc::clone(&auth), headers))
}

async fn get_claims(
    auth: Arc<Authorizer>,
    headers: HeaderMap<HeaderValue>,
) -> Result<Claims, Rejection> {
    let token = token_from_header(&headers).ok_or(reject::custom(Error::InvalidAuthHeader))?;
    let claims = match jsonwebtoken::decode::<Claims>(
        &token,
        &auth.decoding_key,
        &Validation::new(Algorithm::default()),
    ) {
        Ok(token_data) => token_data.claims,
        Err(_) => return Err(reject::custom(Error::JwtFailure)),
    };

    if claims.exp < Utc::now().timestamp() {
        return Err(reject::custom(Error::Unauthorized));
    }

    Ok(claims)
}

pub fn with_auth(
    auth: Arc<Authorizer>,
) -> impl Filter<Extract = (Arc<Authorizer>,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || Arc::clone(&auth))
}

async fn authorize(
    auth: Arc<Authorizer>,
    (role, headers): (Role, HeaderMap<HeaderValue>),
) -> WebResult<String> {
    match token_from_header(&headers) {
        Some(token) => {
            let claims = match jsonwebtoken::decode::<Claims>(
                &token,
                &auth.decoding_key,
                &Validation::new(Algorithm::HS512),
            ) {
                Ok(token_data) => token_data.claims,
                Err(_) => return Err(reject::custom(Error::JwtFailure)),
            };

            if claims.exp < Utc::now().timestamp() {
                return Err(reject::custom(Error::Unauthorized));
            }

            if role == Role::Admin && claims.role != role {
                return Err(reject::custom(Error::Forbidden));
            }

            Ok(claims.uid)
        }

        None => Err(reject::custom(Error::InvalidAuthHeader)),
    }
}

fn token_from_header(headers: &HeaderMap<HeaderValue>) -> Option<String> {
    let auth_header = headers.get(AUTHORIZATION)?;
    let auth_header = auth_header.to_str().ok()?;
    if !auth_header.starts_with(BEARER) {
        return None;
    }
    Some(auth_header.trim_start_matches(BEARER).to_string())
}

pub async fn login_handler(
    auth: Arc<Authorizer>,
    users: Users,
    req: LoginRequest,
) -> WebResult<impl Reply> {
    let user = users
        .iter()
        .find(|u| u.username == req.username && u.pwd == req.pwd);
    match user {
        Some(user) => {
            let token = auth
                .create_token(
                    &user.uid,
                    &Role::parse(&user.role).ok_or(Error::UnknownRole)?,
                )
                .map_err(reject::custom)?;
            Ok(reply::json(&LoginResponse { token }))
        }
        None => Err(reject::custom(Error::Unauthorized)),
    }
}

pub async fn whoami_handler(claims: Claims) -> WebResult<impl Reply> {
    Ok(format!("id: {}, role: {}", claims.uid, claims.role))
}
