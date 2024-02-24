use std::convert::Infallible;
use std::sync::Arc;

// use auth::{login_handler, must_auth, Role};
use auth::Role;
use config::Config;

use clap::Parser;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use warp::{Filter, Rejection, Reply};

mod auth;
mod config;
mod error;

type WebResult<T> = std::result::Result<T, Rejection>;
type Users = Arc<Vec<User>>;

use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};

const JWT_SECRET: &[u8] = b"    ";

#[derive(Clone, Debug)]
pub struct User {
    pub uid: String,
    pub username: String,
    pub pwd: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub pwd: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

pub struct AppState {
    pub users: Users,
    pub authorizer: auth::Authorizer,
}

#[tokio::main]
async fn main() {
    let users = Arc::new(init_users());

    // let auth_handler = Arc::new(auth::Authorizer::new(JWT_SECRET, 3600));

    // let login_route = warp::path!("login")
    //     .and(warp::post())
    //     .and(auth::with_auth(auth_handler.clone()))
    //     .and(with_users(users.clone()))
    //     .and(warp::body::json())
    //     .and_then(login_handler);

    // let user_route = warp::path!("user")
    //     .and(must_auth(Arc::clone(&auth_handler), Role::User))
    //     .and_then(user_handler);

    // let admin_route = warp::path!("admin")
    //     .and(must_auth(Arc::clone(&auth_handler), Role::Admin))
    //     .and_then(admin_handler);

    // let whoami_route = warp::path!("whoami")
    //     .and(auth::extract_claims(Arc::clone(&auth_handler)))
    //     .and_then(auth::whoami_handler);

    // let routes = login_route
    //     .or(user_route)
    //     .or(admin_route)
    //     .or(whoami_route)
    //     .recover(error::handle_rejection);

    // warp::serve(routes).run(([127, 0, 0, 1], 8000)).await;

    dotenv::dotenv().ok();

    // env_logger::init();

    // let config = Config::parse();

    let app_state = AppState {
        users: users.clone(),
        authorizer: auth::Authorizer::new(JWT_SECRET, 3600),
    };

    // let router = Router::new()
    //     // .layer(TraceLayer::new_for_http())
    //     .route("/login", get(root))
    //     .with_state(Arc::new(appState));

    let router = router()
        .merge(auth::router())
        .with_state(Arc::new(app_state));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8070").await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

fn router() -> Router<Arc<AppState>> {
    Router::new().route("/health", get(health_check_handler))
}

async fn health_check_handler() -> &'static str {
    "Healthy!"
}

fn init_users() -> Vec<User> {
    vec![
        User {
            uid: "1".to_string(),
            username: "admin".to_string(),
            pwd: "123".to_string(),
            role: "admin".to_string(),
        },
        User {
            uid: "2".to_string(),
            username: "user".to_string(),
            pwd: "222".to_string(),
            role: "user".to_string(),
        },
        User {
            uid: "2".to_string(),
            username: "user_2".to_string(),
            pwd: "333".to_string(),
            role: "user".to_string(),
        },
    ]
}

// fn with_users(users: Users) -> impl Filter<Extract = (Users,), Error = Infallible> + Clone {
//     warp::any().map(move || users.clone())
// }

// async fn user_handler(uid: String) -> WebResult<impl Reply> {
//     // Ok(reply::json(&format!("User: {}", uid)))
//     Ok(format!("User: {uid}"))
// }

// async fn admin_handler(uid: String) -> WebResult<impl Reply> {
//     Ok(format!("Admin: {uid}"))
// }
