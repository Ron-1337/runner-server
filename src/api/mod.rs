//! The official Runner Hub's web API: Connect RPC with JSON bodies under
//! `/api/runner_server.v1.<Service>/<Method>`, signed in with the session cookie.
//!
//! Differences from the official service: no captcha, no self-registration and
//! no invite codes (those methods answer `unimplemented`); accounts come from an
//! administrator, so AdminService has `CreateUser`, `SetAdmin` and `DeleteUser`.

mod account;
mod admin;
mod auth_service;
mod host;

use crate::{AppState, auth, db, relay};
use axum::{
    Json, Router,
    extract::{FromRequestParts, Request, State},
    http::{HeaderValue, Method, StatusCode, header, request::Parts},
    middleware::{self, Next},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};

const PREFIX: &str = "/api/runner_server.v1";

pub fn routes(state: AppState) -> Router<AppState> {
    Router::new()
        .merge(auth_service::routes())
        .merge(account::routes())
        .merge(host::routes())
        .merge(admin::routes())
        .layer(middleware::from_fn_with_state(state, guard))
}

fn path(service: &str, method: &str) -> String {
    format!("{PREFIX}.{service}/{method}")
}

/// Cookie-authenticated calls must come from this site: a JSON content type
/// (which a cross-site form cannot send without a preflight) and, when the
/// browser says where it came from, this origin.
async fn guard(State(state): State<AppState>, request: Request, next: Next) -> Response {
    if request.method() != Method::POST {
        return ApiError::new("unimplemented", "Use POST.").into_response();
    }
    let json = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(';').next().unwrap_or_default().trim() == "application/json");
    if !json {
        return ApiError::invalid("Content-Type must be application/json.").into_response();
    }
    if let Some(origin) = request.headers().get(header::ORIGIN)
        && origin.to_str().ok() != Some(state.config.origin.as_str())
    {
        return ApiError::new("permission_denied", "Cross-origin request rejected.")
            .into_response();
    }
    next.run(request).await
}

/// `runner_server.v1.ErrorCode`, sent in an `ErrorDetail`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ErrorCode {
    InvalidCredentials = 1,
    UsernameTaken = 4,
    AccountInactive = 5,
    RateLimited = 6,
    SessionExpired = 7,
    UserNotFound = 9,
    CannotDeactivateSelf = 11,
    HostNotFound = 13,
    EnrollmentNotFound = 14,
}

#[derive(Debug)]
pub struct ApiError {
    code: &'static str,
    message: String,
    detail: Option<ErrorCode>,
}

impl ApiError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
        }
    }
    pub fn with(mut self, detail: ErrorCode) -> Self {
        self.detail = Some(detail);
        self
    }
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new("invalid_argument", message)
    }
    pub fn unauthenticated() -> Self {
        Self::new("unauthenticated", "Please sign in.").with(ErrorCode::SessionExpired)
    }
    pub fn not_found(message: &str, detail: ErrorCode) -> Self {
        Self::new("not_found", message).with(detail)
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        tracing::error!("api call failed: {:#}", e.into());
        Self::new("internal", "Internal error.")
    }
}

/// The HTTP status Connect pairs with each error code.
fn status(code: &str) -> StatusCode {
    match code {
        "invalid_argument" | "failed_precondition" | "out_of_range" => StatusCode::BAD_REQUEST,
        "unauthenticated" => StatusCode::UNAUTHORIZED,
        "permission_denied" => StatusCode::FORBIDDEN,
        "not_found" => StatusCode::NOT_FOUND,
        "already_exists" | "aborted" => StatusCode::CONFLICT,
        "resource_exhausted" => StatusCode::TOO_MANY_REQUESTS,
        "unimplemented" => StatusCode::NOT_IMPLEMENTED,
        "unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut body = serde_json::json!({ "code": self.code, "message": self.message });
        if let Some(detail) = self.detail {
            // ErrorDetail { code = 1 (varint) }.
            let bytes = [0x08, detail as u8];
            body["details"] = serde_json::json!([{
                "type": "runner_server.v1.ErrorDetail",
                "value": STANDARD_NO_PAD.encode(bytes),
            }]);
        }
        (status(self.code), Json(body)).into_response()
    }
}

pub type ApiResult<T> = Result<Json<T>, ApiError>;

pub async fn unimplemented() -> ApiError {
    ApiError::new("unimplemented", "Not supported by this server.")
}

/// Reads a request message; an empty body is `{}`.
pub fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    let body = if body.iter().all(u8::is_ascii_whitespace) {
        b"{}".as_slice()
    } else {
        body
    };
    serde_json::from_slice(body).map_err(|_| ApiError::invalid("Malformed request body."))
}

/// A proto3-JSON `uint64`: a string, though a number is accepted too.
pub fn de_id<'de, D: Deserializer<'de>>(d: D) -> Result<i64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Id {
        Text(String),
        Number(i64),
    }
    match Id::deserialize(d)? {
        Id::Number(n) => Ok(n),
        Id::Text(s) if s.is_empty() => Ok(0),
        Id::Text(s) => s.parse().map_err(serde::de::Error::custom),
    }
}

pub fn ts(at: i64) -> Option<String> {
    crate::rpc::rfc3339(at)
}

/// `runner_server.v1.User`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct User {
    id: String,
    username: String,
    display_name: String,
    is_admin: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

impl From<&db::User> for User {
    fn from(u: &db::User) -> Self {
        Self {
            id: u.id.to_string(),
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            is_admin: u.is_admin,
            created_at: ts(u.created_at),
        }
    }
}

#[derive(Serialize)]
pub struct Empty {}

pub fn with_cookie<T: Serialize>(body: T, cookie: &str) -> Result<Response, ApiError> {
    let mut response = Json(body).into_response();
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(cookie).map_err(anyhow::Error::from)?,
    );
    Ok(response)
}

/// The signed-in web user.
pub struct Session(pub auth::CurrentUser);

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        auth::current_user(state, &parts.headers)
            .await?
            .map(Self)
            .ok_or_else(ApiError::unauthenticated)
    }
}

/// The signed-in web user, who is an administrator.
pub struct Admin(pub auth::CurrentUser);

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, ApiError> {
        let Session(me) = Session::from_request_parts(parts, state).await?;
        if !me.user.is_admin {
            return Err(ApiError::new("permission_denied", "Administrators only."));
        }
        Ok(Self(me))
    }
}

/// Disables account [id], signs it out of the web and disconnects its devices.
/// False when there is no such account.
pub async fn deactivate_user(state: &AppState, id: i64) -> anyhow::Result<bool> {
    let hosts = state
        .db
        .call(move |c| {
            if !db::set_disabled(c, id, true)? {
                return Ok(None);
            }
            db::delete_sessions(c, id, None)?;
            db::host_ids_for_user(c, id).map(Some)
        })
        .await?;
    let found = hosts.is_some();
    for host in hosts.unwrap_or_default() {
        state
            .hub
            .kick(host, relay::CLOSE_REMOVED, "account disabled");
    }
    Ok(found)
}

/// Deletes account [id] and disconnects its devices. False when there is none.
pub async fn delete_user(state: &AppState, id: i64) -> anyhow::Result<bool> {
    let hosts = state
        .db
        .call(move |c| {
            let hosts = db::host_ids_for_user(c, id)?;
            Ok(db::delete_user(c, id)?.then_some(hosts))
        })
        .await?;
    let found = hosts.is_some();
    for host in hosts.unwrap_or_default() {
        state
            .hub
            .kick(host, relay::CLOSE_REMOVED, "account deleted");
    }
    Ok(found)
}
