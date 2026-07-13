use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::Row;

use crate::auth::AuthUser;
use crate::AppState;

type ApiError = (StatusCode, &'static str);

// Generous server-side cap: E2EE envelopes are base64 (~4/3 expansion) of
// UTF-8 plaintext capped at 4000 chars client-side.
const MAX_CONTENT_CHARS: usize = 32000;
const HISTORY_PAGE: i64 = 200;

fn internal(_e: sqlx::Error) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, "db error")
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

async fn member_ids(state: &AppState, conversation_id: i64) -> Result<Vec<i64>, ApiError> {
    sqlx::query_scalar("SELECT user_id FROM conversation_members WHERE conversation_id = $1")
        .bind(conversation_id)
        .fetch_all(&state.pool)
        .await
        .map_err(internal)
}

pub async fn list_conversations(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT c.id, c.kind, \
           COALESCE((SELECT string_agg(u.username, ', ') FROM conversation_members m \
                     JOIN users u ON u.id = m.user_id \
                     WHERE m.conversation_id = c.id AND m.user_id <> $1), '') AS peers, \
           (SELECT content FROM messages WHERE conversation_id = c.id \
            ORDER BY id DESC LIMIT 1) AS last_message, \
           (SELECT created_at::text FROM messages WHERE conversation_id = c.id \
            ORDER BY id DESC LIMIT 1) AS last_at, \
           c.retention_days \
         FROM conversations c \
         JOIN conversation_members me ON me.conversation_id = c.id AND me.user_id = $1 \
         ORDER BY COALESCE((SELECT max(id) FROM messages \
                            WHERE conversation_id = c.id), 0) DESC, c.id DESC",
    )
    .bind(user.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;

    let conversations: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>(0),
                "kind": r.get::<String, _>(1),
                "peers": r.get::<String, _>(2),
                "last_message": r.get::<Option<String>, _>(3),
                "last_at": r.get::<Option<String>, _>(4),
                "retention_days": r.get::<Option<i32>, _>(5),
            })
        })
        .collect();
    Ok(Json(json!({ "conversations": conversations })))
}

#[derive(Deserialize)]
pub struct CreateConversationReq {
    kind: String,
    username: Option<String>,
}

pub async fn create_conversation(
    State(state): State<AppState>,
    user: AuthUser,
    Json(req): Json<CreateConversationReq>,
) -> Result<Json<Value>, ApiError> {
    match req.kind.as_str() {
        "self" => {
            let existing: Option<i64> = sqlx::query_scalar(
                "SELECT c.id FROM conversations c \
                 JOIN conversation_members m ON m.conversation_id = c.id \
                 WHERE c.kind = 'self' AND m.user_id = $1 LIMIT 1",
            )
            .bind(user.user_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?;
            if let Some(id) = existing {
                return Ok(Json(json!({ "id": id, "kind": "self" })));
            }
            let mut tx = state.pool.begin().await.map_err(internal)?;
            let id: i64 =
                sqlx::query_scalar("INSERT INTO conversations (kind) VALUES ('self') RETURNING id")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(internal)?;
            sqlx::query("INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2)")
                .bind(id)
                .bind(user.user_id)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            tx.commit().await.map_err(internal)?;
            Ok(Json(json!({ "id": id, "kind": "self" })))
        }
        "p2p" => {
            let username = req
                .username
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or((StatusCode::BAD_REQUEST, "username required for p2p"))?;
            let peer_id: Option<i64> =
                sqlx::query_scalar("SELECT id FROM users WHERE username = $1")
                    .bind(username)
                    .fetch_optional(&state.pool)
                    .await
                    .map_err(internal)?;
            let peer_id = peer_id.ok_or((StatusCode::NOT_FOUND, "no such user"))?;
            if peer_id == user.user_id {
                return Err((
                    StatusCode::BAD_REQUEST,
                    "use a self conversation to message yourself",
                ));
            }
            let existing: Option<i64> = sqlx::query_scalar(
                "SELECT c.id FROM conversations c \
                 JOIN conversation_members a ON a.conversation_id = c.id AND a.user_id = $1 \
                 JOIN conversation_members b ON b.conversation_id = c.id AND b.user_id = $2 \
                 WHERE c.kind = 'p2p' LIMIT 1",
            )
            .bind(user.user_id)
            .bind(peer_id)
            .fetch_optional(&state.pool)
            .await
            .map_err(internal)?;
            if let Some(id) = existing {
                return Ok(Json(json!({ "id": id, "kind": "p2p" })));
            }
            let mut tx = state.pool.begin().await.map_err(internal)?;
            let id: i64 =
                sqlx::query_scalar("INSERT INTO conversations (kind) VALUES ('p2p') RETURNING id")
                    .fetch_one(&mut *tx)
                    .await
                    .map_err(internal)?;
            for uid in [user.user_id, peer_id] {
                sqlx::query(
                    "INSERT INTO conversation_members (conversation_id, user_id) VALUES ($1, $2)",
                )
                .bind(id)
                .bind(uid)
                .execute(&mut *tx)
                .await
                .map_err(internal)?;
            }
            tx.commit().await.map_err(internal)?;
            Ok(Json(json!({ "id": id, "kind": "p2p" })))
        }
        _ => Err((StatusCode::BAD_REQUEST, "kind must be 'p2p' or 'self'")),
    }
}

#[derive(Deserialize)]
pub struct RetentionReq {
    retention_days: Option<i32>,
}

/// Set or clear per-conversation auto-delete. Any member may change it —
/// members share the plaintext anyway, so none of them is more trusted.
pub async fn set_retention(
    State(state): State<AppState>,
    user: AuthUser,
    Path(conversation_id): Path<i64>,
    Json(req): Json<RetentionReq>,
) -> Result<Json<Value>, ApiError> {
    if let Some(days) = req.retention_days {
        if !(1..=365).contains(&days) {
            return Err((StatusCode::BAD_REQUEST, "retention_days must be 1-365"));
        }
    }
    require_member(&state, conversation_id, user.user_id).await?;
    sqlx::query("UPDATE conversations SET retention_days = $1 WHERE id = $2")
        .bind(req.retention_days)
        .bind(conversation_id)
        .execute(&state.pool)
        .await
        .map_err(internal)?;
    Ok(Json(json!({ "retention_days": req.retention_days })))
}

#[derive(Deserialize)]
pub struct HistoryQuery {
    after: Option<i64>,
}

pub async fn list_messages(
    State(state): State<AppState>,
    user: AuthUser,
    Path(conversation_id): Path<i64>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Value>, ApiError> {
    require_member(&state, conversation_id, user.user_id).await?;
    let rows = sqlx::query(
        "SELECT m.id, u.username, m.content, m.created_at::text \
         FROM messages m JOIN users u ON u.id = m.sender_id \
         WHERE m.conversation_id = $1 AND m.id > $2 \
         ORDER BY m.id LIMIT $3",
    )
    .bind(conversation_id)
    .bind(q.after.unwrap_or(0))
    .bind(HISTORY_PAGE)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;

    let messages: Vec<Value> = rows.iter().map(row_to_message).collect();
    Ok(Json(json!({ "messages": messages })))
}

fn row_to_message(r: &sqlx::postgres::PgRow) -> Value {
    json!({
        "id": r.get::<i64, _>(0),
        "sender": r.get::<String, _>(1),
        "content": r.get::<String, _>(2),
        "created_at": r.get::<String, _>(3),
    })
}

#[derive(Deserialize)]
pub struct SendReq {
    content: String,
}

pub async fn send_message(
    State(state): State<AppState>,
    user: AuthUser,
    Path(conversation_id): Path<i64>,
    Json(req): Json<SendReq>,
) -> Result<Json<Value>, ApiError> {
    let content = req.content.trim();
    if content.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty message"));
    }
    if content.chars().count() > MAX_CONTENT_CHARS {
        return Err((StatusCode::BAD_REQUEST, "message too long (max 4000 chars)"));
    }
    require_member(&state, conversation_id, user.user_id).await?;

    let row = sqlx::query(
        "INSERT INTO messages (conversation_id, sender_id, content) VALUES ($1, $2, $3) \
         RETURNING id, created_at::text",
    )
    .bind(conversation_id)
    .bind(user.user_id)
    .bind(content)
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;

    let message = json!({
        "id": row.get::<i64, _>(0),
        "sender": user.username,
        "content": content,
        "created_at": row.get::<String, _>(1),
    });

    let members = member_ids(&state, conversation_id).await?;
    let event = json!({
        "type": "message",
        "conversation_id": conversation_id,
        "message": message,
    });
    state.hub.send_to_users(&members, &event.to_string());

    Ok(Json(message))
}
