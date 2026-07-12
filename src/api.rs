use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};

use crate::auth::{
    generate_code, generate_token, hash_password, hash_token, verify_password, AuthUser,
    SESSION_COOKIE,
};
use crate::AppState;

type ApiError = (StatusCode, &'static str);

const SESSION_DAYS: i64 = 30;

fn internal(_e: sqlx::Error) -> ApiError {
    (StatusCode::INTERNAL_SERVER_ERROR, "db error")
}

fn user_agent(headers: &HeaderMap) -> Option<String> {
    headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.chars().take(256).collect())
}

async fn create_session(
    pool: &PgPool,
    jar: CookieJar,
    user_id: i64,
    ua: Option<String>,
) -> Result<CookieJar, ApiError> {
    let token = generate_token();
    sqlx::query(
        "INSERT INTO sessions (token_hash, user_id, user_agent, expires_at) \
         VALUES ($1, $2, $3, now() + make_interval(days => $4))",
    )
    .bind(hash_token(&token))
    .bind(user_id)
    .bind(ua)
    .bind(SESSION_DAYS as i32)
    .execute(pool)
    .await
    .map_err(internal)?;

    let cookie = Cookie::build((SESSION_COOKIE, token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(time::Duration::days(SESSION_DAYS))
        .build();
    Ok(jar.add(cookie))
}

async fn hash_password_blocking(password: String) -> Result<String, ApiError> {
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash error"))?
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash error"))
}

#[derive(Deserialize)]
pub struct RegisterReq {
    invite: String,
    username: String,
    password: String,
}

pub async fn register(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<RegisterReq>,
) -> Result<(CookieJar, Json<Value>), ApiError> {
    let username = req.username.trim().to_string();
    if username.len() < 3
        || username.len() > 32
        || !username.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "username: 3-32 chars, letters/digits/underscore",
        ));
    }
    if req.password.len() < 8 {
        return Err((StatusCode::BAD_REQUEST, "password: at least 8 characters"));
    }

    let password_hash = hash_password_blocking(req.password).await?;

    let mut tx = state.pool.begin().await.map_err(internal)?;
    let invite = sqlx::query(
        "SELECT code FROM invites \
         WHERE code = $1 AND used_by IS NULL AND expires_at > now() FOR UPDATE",
    )
    .bind(&req.invite)
    .fetch_optional(&mut *tx)
    .await
    .map_err(internal)?;
    if invite.is_none() {
        return Err((StatusCode::BAD_REQUEST, "invalid or expired invite code"));
    }

    let user_id: i64 = match sqlx::query(
        "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id",
    )
    .bind(&username)
    .bind(&password_hash)
    .fetch_one(&mut *tx)
    .await
    {
        Ok(row) => row.get(0),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err((StatusCode::CONFLICT, "username already taken"));
        }
        Err(e) => return Err(internal(e)),
    };

    sqlx::query("UPDATE invites SET used_by = $1 WHERE code = $2")
        .bind(user_id)
        .bind(&req.invite)
        .execute(&mut *tx)
        .await
        .map_err(internal)?;
    tx.commit().await.map_err(internal)?;

    let jar = create_session(&state.pool, jar, user_id, user_agent(&headers)).await?;
    Ok((jar, Json(json!({ "username": username }))))
}

#[derive(Deserialize)]
pub struct LoginReq {
    username: String,
    password: String,
}

pub async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Result<(CookieJar, Json<Value>), ApiError> {
    let row = sqlx::query("SELECT id, username, password_hash FROM users WHERE username = $1")
        .bind(req.username.trim())
        .fetch_optional(&state.pool)
        .await
        .map_err(internal)?;

    // Verify against a dummy hash when the user is unknown so response time
    // does not reveal whether the username exists.
    let (user_id, username, stored_hash) = match &row {
        Some(r) => (r.get::<i64, _>(0), r.get::<String, _>(1), r.get::<String, _>(2)),
        None => (0, String::new(), state.dummy_hash.as_ref().clone()),
    };

    let password = req.password;
    let valid = tokio::task::spawn_blocking(move || verify_password(&password, &stored_hash))
        .await
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "hash error"))?;

    if row.is_none() || !valid {
        return Err((StatusCode::UNAUTHORIZED, "invalid username or password"));
    }

    let jar = create_session(&state.pool, jar, user_id, user_agent(&headers)).await?;
    Ok((jar, Json(json!({ "username": username }))))
}

pub async fn logout(
    State(state): State<AppState>,
    user: AuthUser,
    jar: CookieJar,
) -> Result<(CookieJar, Json<Value>), ApiError> {
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(&user.token_hash)
        .execute(&state.pool)
        .await
        .map_err(internal)?;
    Ok((jar.remove(SESSION_COOKIE), Json(json!({}))))
}

pub async fn me(user: AuthUser) -> Json<Value> {
    Json(json!({ "username": user.username }))
}

pub async fn list_sessions(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT id, user_agent, created_at::text, token_hash = $2 AS current \
         FROM sessions WHERE user_id = $1 AND expires_at > now() \
         ORDER BY created_at DESC",
    )
    .bind(user.user_id)
    .bind(&user.token_hash)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;

    let sessions: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "id": r.get::<i64, _>(0),
                "user_agent": r.get::<Option<String>, _>(1),
                "created_at": r.get::<String, _>(2),
                "current": r.get::<bool, _>(3),
            })
        })
        .collect();
    Ok(Json(json!({ "sessions": sessions })))
}

pub async fn revoke_session(
    State(state): State<AppState>,
    user: AuthUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, ApiError> {
    let result = sqlx::query("DELETE FROM sessions WHERE id = $1 AND user_id = $2")
        .bind(id)
        .bind(user.user_id)
        .execute(&state.pool)
        .await
        .map_err(internal)?;
    if result.rows_affected() == 0 {
        return Err((StatusCode::NOT_FOUND, "no such session"));
    }
    Ok(Json(json!({})))
}

pub async fn create_invite(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let code = generate_code();
    let row = sqlx::query(
        "INSERT INTO invites (code, created_by, expires_at) \
         VALUES ($1, $2, now() + interval '7 days') RETURNING expires_at::text",
    )
    .bind(&code)
    .bind(user.user_id)
    .fetch_one(&state.pool)
    .await
    .map_err(internal)?;
    Ok(Json(json!({
        "code": code,
        "expires_at": row.get::<String, _>(0),
    })))
}

pub async fn list_invites(
    State(state): State<AppState>,
    user: AuthUser,
) -> Result<Json<Value>, ApiError> {
    let rows = sqlx::query(
        "SELECT code, used_by IS NOT NULL AS used, expires_at::text, expires_at > now() AS live \
         FROM invites WHERE created_by = $1 ORDER BY created_at DESC",
    )
    .bind(user.user_id)
    .fetch_all(&state.pool)
    .await
    .map_err(internal)?;

    let invites: Vec<Value> = rows
        .iter()
        .map(|r| {
            json!({
                "code": r.get::<String, _>(0),
                "used": r.get::<bool, _>(1),
                "expires_at": r.get::<String, _>(2),
                "live": r.get::<bool, _>(3),
            })
        })
        .collect();
    Ok(Json(json!({ "invites": invites })))
}
