//! AuthService: sign in, keep the session alive, sign out. No captcha and no
//! registration: `GetCaptcha` and `Register` answer `unimplemented`.

use super::{ApiError, Empty, ErrorCode, Session, User, parse, path, unimplemented, with_cookie};
use crate::{AppState, auth, db, now};
use axum::{
    Router, body::Bytes, extract::State, http::HeaderMap, response::Response, routing::post,
};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    let at = |m| path("AuthService", m);
    Router::new()
        .route(&at("SignIn"), post(sign_in))
        .route(&at("Refresh"), post(refresh))
        .route(&at("SignOut"), post(sign_out))
        .route(&at("SignOutEverywhere"), post(sign_out_everywhere))
        .route(&at("GetCaptcha"), post(unimplemented))
        .route(&at("Register"), post(unimplemented))
}

/// Captcha fields, if a client sends them, are ignored.
#[derive(Default, Deserialize)]
#[serde(default)]
struct SignInRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignInResponse {
    user: User,
    /// Told only once signed in, as GetMe does.
    server_version: &'static str,
}

async fn sign_in(State(state): State<AppState>, body: Bytes) -> Result<Response, ApiError> {
    let request: SignInRequest = parse(&body)?;
    let key = request.username.trim().to_lowercase();
    if !state.limiter.allowed(&key) {
        return Err(ApiError::new(
            "resource_exhausted",
            "Too many failed sign-ins; try again in 15 minutes.",
        )
        .with(ErrorCode::RateLimited));
    }
    let lookup = request.username.trim().to_owned();
    let found = state
        .db
        .call(move |c| db::user_with_hash(c, &lookup))
        .await?;
    let (user, hash) = match found {
        Some((u, h)) => (Some(u), Some(h)),
        None => (None, None),
    };
    let password = request.password;
    let valid =
        tokio::task::spawn_blocking(move || auth::verify_password(&password, hash.as_deref()))
            .await?;
    let user = match user {
        Some(u) if valid && !u.disabled => u,
        Some(u) if valid && u.disabled => {
            return Err(
                ApiError::new("permission_denied", "This account is deactivated.")
                    .with(ErrorCode::AccountInactive),
            );
        }
        _ => {
            state.limiter.fail(&key);
            return Err(
                ApiError::new("unauthenticated", "Wrong username or password.")
                    .with(ErrorCode::InvalidCredentials),
            );
        }
    };
    state.limiter.clear(&key);
    let token = auth::start_session(&state, user.id).await?;
    let id = user.id;
    state
        .db
        .call(move |c| db::touch_login(c, id, now()))
        .await?;
    with_cookie(
        SignInResponse {
            user: User::from(&user),
            server_version: crate::html::VERSION,
        },
        &auth::session_cookie(&token, state.config.secure_cookies),
    )
}

/// Extends the session cookie's life; the client calls it when a call fails
/// with `unauthenticated`, so a gone session answers that too.
async fn refresh(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    let token =
        auth::cookie_value(&headers, auth::SESSION_COOKIE).ok_or_else(ApiError::unauthenticated)?;
    if auth::current_user(&state, &headers).await?.is_none() {
        return Err(ApiError::unauthenticated());
    }
    let hash = auth::sha256_hex(&token);
    let now = now();
    let extended = state
        .db
        .call(move |c| db::extend_session(c, &hash, now + auth::SESSION_TTL, now))
        .await?;
    if !extended {
        return Err(ApiError::unauthenticated());
    }
    with_cookie(
        Empty {},
        &auth::session_cookie(&token, state.config.secure_cookies),
    )
}

async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> Result<Response, ApiError> {
    if let Some(token) = auth::cookie_value(&headers, auth::SESSION_COOKIE) {
        let hash = auth::sha256_hex(&token);
        state.db.call(move |c| db::delete_session(c, &hash)).await?;
    }
    with_cookie(Empty {}, &auth::clear_cookie(state.config.secure_cookies))
}

/// Ends every web session of the account. Devices stay signed in.
async fn sign_out_everywhere(
    State(state): State<AppState>,
    Session(me): Session,
) -> Result<Response, ApiError> {
    let id = me.user.id;
    state
        .db
        .call(move |c| db::delete_sessions(c, id, None))
        .await?;
    with_cookie(Empty {}, &auth::clear_cookie(state.config.secure_cookies))
}
