mod api;
mod auth;
mod chat;
mod ws;

use std::sync::Arc;

use axum::routing::{delete, get, post};
use axum::{Json, Router};
use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use tower_http::services::ServeDir;

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    /// Valid Argon2 hash of a random string; used to equalize login timing
    /// for unknown usernames.
    pub dummy_hash: Arc<String>,
    pub hub: ws::Hub,
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok", "version": env!("CARGO_PKG_VERSION") }))
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/register", post(api::register))
        .route("/api/login", post(api::login))
        .route("/api/logout", post(api::logout))
        .route("/api/me", get(api::me))
        .route("/api/sessions", get(api::list_sessions))
        .route("/api/sessions/{id}", delete(api::revoke_session))
        .route("/api/invites", get(api::list_invites).post(api::create_invite))
        .route("/api/ws", get(ws::ws_handler))
        .route(
            "/api/conversations",
            get(chat::list_conversations).post(chat::create_conversation),
        )
        .route(
            "/api/conversations/{id}/messages",
            get(chat::list_messages).post(chat::send_message),
        )
        .fallback_service(ServeDir::new("static"))
        .with_state(state)
}

/// If no users exist yet, make sure a bootstrap invite is available and print
/// it to the logs so the first account can be registered.
async fn bootstrap_invite(pool: &PgPool) {
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
        .fetch_one(pool)
        .await
        .expect("failed to count users");
    if users > 0 {
        return;
    }
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT code FROM invites \
         WHERE created_by IS NULL AND used_by IS NULL AND expires_at > now() LIMIT 1",
    )
    .fetch_optional(pool)
    .await
    .expect("failed to check invites");
    let code = match existing {
        Some(code) => code,
        None => {
            let code = auth::generate_code();
            sqlx::query(
                "INSERT INTO invites (code, expires_at) VALUES ($1, now() + interval '7 days')",
            )
            .bind(&code)
            .execute(pool)
            .await
            .expect("failed to create bootstrap invite");
            code
        }
    };
    println!("=================================================");
    println!("  BOOTSTRAP INVITE CODE: {code}");
    println!("  Register the first account with this code.");
    println!("=================================================");
}

#[tokio::main]
async fn main() {
    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL not set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("failed to connect to database");
    sqlx::migrate!().run(&pool).await.expect("migrations failed");
    bootstrap_invite(&pool).await;

    let state = AppState {
        pool,
        dummy_hash: Arc::new(
            auth::hash_password(&auth::generate_token()).expect("failed to create dummy hash"),
        ),
        hub: ws::Hub::default(),
    };

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind port");
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app(state)).await.unwrap();
}
