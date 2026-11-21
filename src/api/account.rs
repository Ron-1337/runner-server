//! AccountService: the signed-in user and their password.

use super::{ApiError, ApiResult, Empty, ErrorCode, Session, User, parse, path};
use crate::{AppState, auth, db};
use axum::{Json, Router, body::Bytes, extract::State, routing::post};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    let at = |m| path("AccountService", m);
    Router::new()
        .route(&at("GetMe"), post(get_me))
        .route(&at("ChangePassword"), post(change_password))
}

#[derive(Serialize)]
struct GetMeResponse {
    user: User,
}

async fn get_me(Session(me): Session) -> ApiResult<GetMeResponse> {
    Ok(Json(GetMeResponse {
        user: User::from(&me.user),
    }))
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct ChangePasswordRequest {
    #[serde(alias = "current_password")]
    current_password: String,
    #[serde(alias = "new_password")]
    new_password: String,
}

/// Signs the account out of its other web sessions; devices are not affected.
async fn change_password(
    State(state): State<AppState>,
    Session(me): Session,
    body: Bytes,
) -> ApiResult<Empty> {
    let request: ChangePasswordRequest = parse(&body)?;
    auth::validate_password(&request.new_password, &request.new_password)
        .map_err(ApiError::invalid)?;
    let user_id = me.user.id;
    let hash = state
        .db
        .call(move |c| db::password_hash(c, user_id))
        .await?;
    let current = request.current_password;
    let valid =
        tokio::task::spawn_blocking(move || auth::verify_password(&current, hash.as_deref()))
            .await?;
    if !valid {
        // Not `unauthenticated`: the client would take that as an expired session.
        return Err(
            ApiError::invalid("The current password is wrong.").with(ErrorCode::InvalidCredentials)
        );
    }
    let password = request.new_password;
    let new_hash = tokio::task::spawn_blocking(move || auth::hash_password(&password)).await??;
    let keep = me.session;
    state
        .db
        .call(move |c| {
            db::set_password(c, user_id, &new_hash)?;
            db::delete_sessions(c, user_id, Some(&keep))
        })
        .await?;
    Ok(Json(Empty {}))
}
