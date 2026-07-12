use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::auth::AuthUser;
use crate::AppState;

type ApiError = (StatusCode, &'static str);

// base64url of 32 bytes = 43 chars; allow some slack but reject garbage.
const MAX_KEY_FIELD: usize = 128;
const MAX_WRAPPED_FIELD: usize = 256;

fn internal(_e: sqlx::Error) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, "db error")
}

fn field_ok(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

async fn require_member(
    state: &AppState,
    conversation_id: i64,
    user_id: i64,
) -> Result<(), ApiError> {
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM conversation_members \
         WHERE conversation_id = $1 AND user_id = $2)",
    )
    .bind(conversation_id)
    .bind(user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;
    if !is_member {
        return Err((StatusCode::NOT_FOUND, "no such conversation"));
    }
    Ok(())
}

#[derive(Deserialize)]
pub struct RegisterDeviceReq {
    name: Option<String>,
    public_key: String,
}

pub async fn register_device(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<RegisterDeviceReq>,
) -> Result<Json<Value>, ApiError> {
    if !field_ok(&req.public_key, MAX_KEY_FIELD) {
        return Err((StatusCode::BAD_REQUEST, "invalid public key"));
    }
    let name: Option<String> = req.name.map(|n| n.chars().take(64).collect());
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO devices (user_id, name, public_key) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(user.user_id)
    .bind(&name)
    .bind(&req.public_key)
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;

    // Nudge everyone who shares a conversation with this user (including the
    // user's own other devices): key-holding clients react by wrapping the
    // conversation key for the new device — no manual reload needed.
    let peers: Vec<i64> = sqlx::query_scalar(
        "SELECT DISTINCT m2.user_id FROM conversation_members m1 \
         JOIN conversation_members m2 ON m2.conversation_id = m1.conversation_id \
         WHERE m1.user_id = $1",
    )
    .bind(user.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    state
        .hub
        .send_to_users(&peers, r#"{"type":"sync_keys"}"#);

    Ok(Json(json!({ "id": id })))
}

/// Ids of the caller's own registered devices — lets a client detect that its
/// locally stored device identity is stale (e.g. server DB was reset).
pub async fn list_my_devices(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM devices WHERE user_id = $1")
        .bind(user.user_id)
        .fetch_all(&state.pool)
        .await
        .map_err(internal)?;
    Ok(Json(json!({ "device_ids": ids })))
}

/// All devices of all members of a conversation, with per-device key status.
/// The client uses this to (a) find devices still lacking a wrapped key and
/// (b) get the public keys needed to wrap for them.
pub async fn conversation_devices(
    State(state): State<AppState>,
    user: AuthUser,
    Path(conversation_id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    require_member(&state, conversation_id, user.user_id).await?;
    let rows = sqlx::query(
        "SELECT d.id, u.username, d.public_key, \
                EXISTS(SELECT 1 FROM conversation_keys k \
                       WHERE k.conversation_id = $1 AND k.device_id = d.id) AS has_key \
         FROM devices d \
         JOIN users u ON u.id = d.user_id \
         JOIN conversation_members m ON m.user_id = d.user_id \
         WHERE m.conversation_id = $1 \
         ORDER BY d.id",
    )
    .bind(conversation_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;

    let devices: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "device_id": r.get::<i64, _>(0),
                "username": r.get::<String, _>(1),
                "public_key": r.get::<String, _>(2),
                "has_key": r.get::<bool, _>(3),
            })
        })
        .collect();
    Ok(Json(json!({ "devices": devices })))
}

#[derive(Deserialize)]
pub struct KeyQuery {
    device_id: i64,
}

/// Fetch the wrapped conversation key for one of the caller's own devices.
pub async fn get_conversation_key(
    State(state): State<AppState>,
    user: AuthUser,
    Path(conversation_id): Path<i64>,
    Query(q): Query<KeyQuery>,
) -> Result<Json<Value>, ApiError> {
    require_member(&state, conversation_id, user.user_id).await?;
    let owns: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM devices WHERE id = $1 AND user_id = $2)")
            .bind(q.device_id)
            .bind(user.user_id)
            .fetch_one(&state.pool)
            .await
            .map_err(internal)?;
    if !owns {
        return Err((StatusCode::NOT_FOUND, "no such device"));
    }
    let row = sqlx::query(
        "SELECT wrapped_key, nonce, wrapper_pub FROM conversation_keys \
         WHERE conversation_id = $1 AND device_id = $2",
    )
    .bind(conversation_id)
    .bind(q.device_id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;
    match row {
        Some(r) => Ok(Json(json!({
            "wrapped_key": r.get::<String, _>(0),
            "nonce": r.get::<String, _>(1),
            "wrapper_pub": r.get::<String, _>(2),
        }))),
        None => {
            // A device is asking for a key it doesn't have: nudge the other
            // members so any online key-holder wraps for it immediately.
            let members: Vec<i64> = sqlx::query_scalar(
                "SELECT user_id FROM conversation_members WHERE conversation_id = $1",
            )
            .bind(conversation_id)
            .fetch_all(&state.pool)
            .await
            .map_err(internal)?;
            state.hub.send_to_users(&members, r#"{"type":"sync_keys"}"#);
            Err((StatusCode::NOT_FOUND, "no key for this device yet"))
        }
    }
}

#[derive(Deserialize)]
pub struct WrapEntry {
    device_id: i64,
    wrapped_key: String,
    nonce: String,
    wrapper_pub: String,
}

#[derive(Deserialize)]
pub struct PostKeysReq {
    /// True when this batch establishes the conversation key for the first
    /// time. Guarded by a transaction so two racing clients cannot seed two
    /// different keys — the loser gets 409 and refetches.
    #[serde(default)]
    initial: bool,
    entries: Vec<WrapEntry>,
}

pub async fn post_conversation_keys(
    State(state): State<AppState>,
    user: AuthUser,
    Path(conversation_id): Path<i64>,
    Json(req): Json<PostKeysReq>,
) -> Result<Json<Value>, ApiError> {
    require_member(&state, conversation_id, user.user_id).await?;
    if req.entries.is_empty() || req.entries.len() > 64 {
        return Err((StatusCode::BAD_REQUEST, "1-64 entries required"));
    }
    for e in &req.entries {
        if !field_ok(&e.wrapped_key, MAX_WRAPPED_FIELD)
            || !field_ok(&e.nonce, MAX_KEY_FIELD)
            || !field_ok(&e.wrapper_pub, MAX_KEY_FIELD)
        {
            return Err((StatusCode::BAD_REQUEST, "invalid key material"));
        }
    }

    let mut tx = state.pool.begin().await.map_err(internal)?;
    // Serialize concurrent key seeding per conversation (aggregate queries
    // cannot take row locks, and there may be no rows to lock yet).
    sqlx::query("SELECT pg_advisory_xact_lock(772026, $1)")
        .bind(conversation_id as i32)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    let existing: i64 =
        sqlx::query_scalar("SELECT count(*) FROM conversation_keys WHERE conversation_id = $1")
            .bind(conversation_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(internal)?;
    if req.initial && existing > 0 {
        return Err((StatusCode::CONFLICT, "conversation key already established"));
    }

    for e in &req.entries {
        // Target device must belong to a member of this conversation.
        let valid_target: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM devices d \
             JOIN conversation_members m ON m.user_id = d.user_id \
             WHERE d.id = $1 AND m.conversation_id = $2)",
        )
        .bind(e.device_id)
        .bind(conversation_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(internal)?;
        if !valid_target {
            return Err((StatusCode::BAD_REQUEST, "device is not in this conversation"));
        }
        sqlx::query(
            "INSERT INTO conversation_keys \
             (conversation_id, device_id, wrapped_key, nonce, wrapper_pub) \
             VALUES ($1, $2, $3, $4, $5) \
             ON CONFLICT (conversation_id, device_id) DO NOTHING",
        )
        .bind(conversation_id)
        .bind(e.device_id)
        .bind(&e.wrapped_key)
        .bind(&e.nonce)
        .bind(&e.wrapper_pub)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    }
    tx.commit().await.map_err(internal)?;

    // Tell members fresh keys landed; a device stuck on "waiting for key"
    // retries immediately instead of waiting for a manual reload.
    let members: Vec<i64> = sqlx::query_scalar(
        "SELECT user_id FROM conversation_members WHERE conversation_id = $1",
    )
    .bind(conversation_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;
    let event = json!({ "type": "keys_updated", "conversation_id": conversation_id });
    state.hub.send_to_users(&members, &event.to_string());

    Ok(Json(json!({})))
}
