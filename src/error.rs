use serde::Serialize;
use std::convert::Infallible;
use thiserror::Error;
// use warp::{http::StatusCode, Rejection, Reply};

use axum::{
    async_trait,
    extract::{FromRequestParts, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, RequestPartsExt, Router,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid auth header")]
    InvalidAuthHeader,
    #[error("jwt error")]
    JwtFailure,
    #[error("forbidden")]
    Forbidden,
    #[error("unauthenticated")]
    Unauthorized,
    #[error("unknown role")]
    UnknownRole,
}

#[derive(Serialize)]
struct ErrorResponse {
    message: String,
    // status: u16,
}

// impl warp::reject::Reject for Error {}

// pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
//     let code;
//     let message;
//     if err.is_not_found() {
//         code = StatusCode::NOT_FOUND;
//         message = "Not Found".to_owned();
//     } else if let Some(e) = err.find::<Error>() {
//         match e {
//             Error::InvalidAuthHeader => {
//                 code = StatusCode::BAD_REQUEST;
//                 message = e.to_string();
//             }
//             Error::JwtFailure => {
//                 code = StatusCode::UNAUTHORIZED;
//                 message = e.to_string();
//             }
//             Error::Forbidden => {
//                 code = StatusCode::FORBIDDEN;
//                 message = e.to_string();
//             }
//             Error::Unauthorized => {
//                 code = StatusCode::UNAUTHORIZED;
//                 message = e.to_string();
//             }
//             Error::UnknownRole => {
//                 code = StatusCode::BAD_REQUEST;
//                 message = e.to_string();
//             }
//         }
//     } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
//         code = StatusCode::METHOD_NOT_ALLOWED;
//         message = "Method Not Allowed".to_owned();
//     } else {
//         eprintln!("Error: unhandled rejection: {:?}", err);
//         code = StatusCode::INTERNAL_SERVER_ERROR;
//         message = "Internal Server Error".to_owned();
//     }
//     let json = warp::reply::json(&ErrorResponse {
//         message,
//         status: code.as_u16(),
//     });
//     Ok(warp::reply::with_status(json, code))
// }

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            // AuthError::WrongCredentials => (StatusCode::UNAUTHORIZED, "Wrong credentials"),
            // AuthError::MissingCredentials => (StatusCode::BAD_REQUEST, "Missing credentials"),
            // AuthError::TokenCreation => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation error"),
            // AuthError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
            Error::InvalidAuthHeader => (StatusCode::BAD_REQUEST, "Invalid auth header"),
            Error::JwtFailure => (StatusCode::UNAUTHORIZED, "JWT failure"),
            Error::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized"),
            Error::UnknownRole => (StatusCode::BAD_REQUEST, "Unknown role"),
        };
        let body = Json(ErrorResponse {
            message: error_message.to_string(),
        });
        (status, body).into_response()
    }
}
