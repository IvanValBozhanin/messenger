use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

use crate::auth::AuthUser;
use crate::AppState;

type ApiError = (StatusCode, &'static str);

/// Client-side plaintext cap is 10 MB; ciphertext adds a 16-byte GCM tag, and
/// we leave headroom. Enforced both here and via the route body limit.
pub const MAX_ATTACHMENT_BYTES: usize = 11 * 1024 * 1024;

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

/// Upload one encrypted blob (raw request body = ciphertext). The server
/// never learns the content type, file name, or plaintext — those travel
/// inside the encrypted message envelope that references this attachment.
pub async fn upload(
    State(state): State<AppState>,
    user: AuthUser,
    Path(conversation_id): Path<i64>,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    if body.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "empty attachment"));
    }
    if body.len() > MAX_ATTACHMENT_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "attachment too large (max 10 MB)"));
    }
    require_member(&state, conversation_id, user.user_id).await?;
    let id: i64 = sqlx::query_scalar(
        "INSERT INTO attachments (conversation_id, sender_id, data) \
         VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(conversation_id)
    .bind(user.user_id)
    .bind(body.as_ref())
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!({ "id": id })))
}

pub async fn download(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Response, ApiError> {
    let row: Option<(i64, Vec<u8>)> = sqlx::query_as(
        "SELECT conversation_id, data FROM attachments WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&state.pool)
    .await
    .map_err(internal)?;
    let Some((conversation_id, data)) = row else {
        return Err((StatusCode::NOT_FOUND, "no such attachment"));
    };
    require_member(&state, conversation_id, user.user_id).await?;
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "private, max-age=31536000, immutable"),
        ],
        data,
    )
        .into_response())
}
