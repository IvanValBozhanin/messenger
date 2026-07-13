mod api;
mod attachments;
mod auth;
mod chat;
mod keys;
mod limit;
mod ws;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::http::header::{HeaderName, HeaderValue};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, patch, post};
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
    pub limiter: Arc<limit::RateLimiter>,
}

/// XSS is total defeat for browser-held keys, so the CSP is strict: nothing
/// executes or loads unless we shipped it; blob: only where decrypted media
/// needs it.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
     img-src 'self' blob:; media-src 'self' blob:; connect-src 'self'; \
     object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";

async fn security_headers(req: Request, next: Next) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, name: &'static str, value: &'static str| {
        h.insert(
            HeaderName::from_static(name),
            HeaderValue::from_static(value),
        );
    };
    set(h, "content-security-policy", CSP);
    set(
        h,
        "strict-transport-security",
        "max-age=31536000; includeSubDomains",
    );
    set(h, "x-content-type-options", "nosniff");
    set(h, "referrer-policy", "no-referrer");
    res
}

/// Data minimization: with static keys (no forward secrecy), deleted
/// ciphertext is the only thing a future key compromise can never decrypt.
async fn retention_sweep(pool: &PgPool) {
    for table in ["messages", "attachments"] {
        let sql = format!(
            "DELETE FROM {table} t USING conversations c \
             WHERE c.id = t.conversation_id AND c.retention_days IS NOT NULL \
             AND t.created_at < now() - make_interval(days => c.retention_days)"
        );
        if let Err(e) = sqlx::query(&sql).execute(pool).await {
            eprintln!("retention sweep failed for {table}: {e}");
        }
    }
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
        .route("/api/conversations/{id}", patch(chat::set_retention))
        .route(
            "/api/conversations/{id}/messages",
            get(chat::list_messages).post(chat::send_message),
        )
        .route(
            "/api/devices",
            get(keys::list_my_devices).post(keys::register_device),
        )
        .route(
            "/api/conversations/{id}/devices",
            get(keys::conversation_devices),
        )
        .route(
            "/api/conversations/{id}/keys",
            get(keys::get_conversation_key).post(keys::post_conversation_keys),
        )
        .route(
            "/api/conversations/{id}/attachments",
            post(attachments::upload).layer(axum::extract::DefaultBodyLimit::max(
                attachments::MAX_ATTACHMENT_BYTES + 1024,
            )),
        )
        .route("/api/attachments/{id}", get(attachments::download))
        .fallback_service(ServeDir::new("static"))
        .layer(middleware::from_fn(security_headers))
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
        pool: pool.clone(),
        dummy_hash: Arc::new(
            auth::hash_password(&auth::generate_token()).expect("failed to create dummy hash"),
        ),
        hub: ws::Hub::default(),
        limiter: Arc::new(limit::RateLimiter::default()),
    };

    tokio::spawn(async move {
        loop {
            retention_sweep(&pool).await;
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8000);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .expect("failed to bind port");
    println!("listening on {}", listener.local_addr().unwrap());
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .unwrap();
}
