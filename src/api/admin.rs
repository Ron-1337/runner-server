//! AdminService: accounts, for administrators. Invites are not supported; this
//! server adds `CreateUser`, `SetAdmin` and `DeleteUser` instead, because only
//! administrators create accounts here.

use super::{
    Admin, ApiError, ApiResult, Empty, ErrorCode, User, de_id, deactivate_user, delete_user, parse,
    path, ts, unimplemented,
};
use crate::{AppState, auth, db, now};
use axum::{Json, Router, body::Bytes, extract::State, routing::post};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    let at = |m| path("AdminService", m);
    Router::new()
        .route(&at("ListUsers"), post(list_users))
        .route(&at("DeactivateUser"), post(deactivate))
        .route(&at("ReactivateUser"), post(reactivate))
        .route(&at("ResetPassword"), post(reset_password))
        .route(&at("CreateUser"), post(create_user))
        .route(&at("SetAdmin"), post(set_admin))
        .route(&at("DeleteUser"), post(delete))
        .route(&at("CreateInvite"), post(unimplemented))
        .route(&at("ListInvites"), post(unimplemented))
        .route(&at("RevokeInvite"), post(unimplemented))
}

/// `runner_server.v1.AdminUser`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdminUser {
    user: User,
    status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_login_at: Option<String>,
}

#[derive(Serialize)]
struct ListUsersResponse {
    users: Vec<AdminUser>,
}

async fn list_users(
    State(state): State<AppState>,
    Admin(_): Admin,
) -> ApiResult<ListUsersResponse> {
    let users = state.db.call(|c| db::list_users(c)).await?;
    Ok(Json(ListUsersResponse {
        users: users
            .iter()
            .map(|u| AdminUser {
                user: User::from(u),
                status: if u.disabled {
                    "USER_STATUS_INACTIVE"
                } else {
                    "USER_STATUS_ACTIVE"
                },
                last_login_at: u.last_login_at.and_then(ts),
            })
            .collect(),
    }))
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct UserRequest {
    #[serde(alias = "user_id", deserialize_with = "de_id")]
    user_id: i64,
    #[serde(alias = "is_admin")]
    is_admin: bool,
}

fn user_not_found() -> ApiError {
    ApiError::not_found("No such user.", ErrorCode::UserNotFound)
}

/// Administrators cannot lock themselves out.
fn not_self(me: &db::User, id: i64) -> Result<(), ApiError> {
    if me.id == id {
        return Err(ApiError::new(
            "failed_precondition",
            "You cannot do this to your own account.",
        )
        .with(ErrorCode::CannotDeactivateSelf));
    }
    Ok(())
}

async fn deactivate(
    State(state): State<AppState>,
    Admin(me): Admin,
    body: Bytes,
) -> ApiResult<Empty> {
    let request: UserRequest = parse(&body)?;
    not_self(&me.user, request.user_id)?;
    if !deactivate_user(&state, request.user_id).await? {
        return Err(user_not_found());
    }
    tracing::info!(user = request.user_id, "user deactivated");
    Ok(Json(Empty {}))
}

async fn reactivate(
    State(state): State<AppState>,
    Admin(_): Admin,
    body: Bytes,
) -> ApiResult<Empty> {
    let request: UserRequest = parse(&body)?;
    let id = request.user_id;
    if !state
        .db
        .call(move |c| db::set_disabled(c, id, false))
        .await?
    {
        return Err(user_not_found());
    }
    tracing::info!(user = id, "user reactivated");
    Ok(Json(Empty {}))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ResetPasswordResponse {
    temporary_password: String,
}

/// Sets a random password and signs the user out of the web.
async fn reset_password(
    State(state): State<AppState>,
    Admin(me): Admin,
    body: Bytes,
) -> ApiResult<ResetPasswordResponse> {
    let request: UserRequest = parse(&body)?;
    not_self(&me.user, request.user_id)?;
    let password = auth::temporary_password();
    let copy = password.clone();
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&copy)).await??;
    let id = request.user_id;
    let found = state
        .db
        .call(move |c| {
            let found = db::set_password(c, id, &hash)?;
            db::delete_sessions(c, id, None)?;
            Ok(found)
        })
        .await?;
    if !found {
        return Err(user_not_found());
    }
    tracing::info!(user = id, "password reset by admin");
    Ok(Json(ResetPasswordResponse {
        temporary_password: password,
    }))
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct CreateUserRequest {
    username: String,
    #[serde(alias = "display_name")]
    display_name: String,
    password: String,
    #[serde(alias = "is_admin")]
    is_admin: bool,
}

#[derive(Serialize)]
struct CreateUserResponse {
    user: User,
}

async fn create_user(
    State(state): State<AppState>,
    Admin(_): Admin,
    body: Bytes,
) -> ApiResult<CreateUserResponse> {
    let request: CreateUserRequest = parse(&body)?;
    let (username, display) = auth::new_user_fields(
        &request.username,
        &request.display_name,
        &request.password,
        &request.password,
    )
    .map_err(ApiError::invalid)?;
    let password = request.password;
    let hash = tokio::task::spawn_blocking(move || auth::hash_password(&password)).await??;
    let is_admin = request.is_admin;
    let name = username.clone();
    let user = state
        .db
        .call(
            move |c| match db::insert_user(c, &name, &display, &hash, is_admin, now())? {
                Some(id) => db::user_by_id(c, id),
                None => Ok(None),
            },
        )
        .await?
        .ok_or_else(|| {
            ApiError::new("already_exists", "That username is taken.")
                .with(ErrorCode::UsernameTaken)
        })?;
    tracing::info!(user = %username, "user created");
    Ok(Json(CreateUserResponse {
        user: User::from(&user),
    }))
}

async fn set_admin(
    State(state): State<AppState>,
    Admin(me): Admin,
    body: Bytes,
) -> ApiResult<Empty> {
    let request: UserRequest = parse(&body)?;
    not_self(&me.user, request.user_id)?;
    let (id, admin) = (request.user_id, request.is_admin);
    if !state.db.call(move |c| db::set_admin(c, id, admin)).await? {
        return Err(user_not_found());
    }
    tracing::info!(user = id, admin, "user role changed");
    Ok(Json(Empty {}))
}

async fn delete(State(state): State<AppState>, Admin(me): Admin, body: Bytes) -> ApiResult<Empty> {
    let request: UserRequest = parse(&body)?;
    not_self(&me.user, request.user_id)?;
    if !delete_user(&state, request.user_id).await? {
        return Err(user_not_found());
    }
    tracing::info!(user = request.user_id, "user deleted");
    Ok(Json(Empty {}))
}
