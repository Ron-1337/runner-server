use crate::{AppState, auth, db, now, relay};
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat};
use runner_core::remote::{
    self, Account, Computer, EnrollmentState, HostInfo, PollRequest, PollResponse, Secret,
    StartRequest, StartResponse,
};
use serde::{Serialize, de::DeserializeOwned};

pub const ENROLLMENT_TTL: i64 = 600;
pub const CLAIM_TTL: i64 = 600;
pub const POLL_INTERVAL: i32 = 5;
const MAX_PENDING_ENROLLMENTS: i64 = 1000;
const ENROLL: &str = "/api/runner_server.v1.HostEnrollmentService";
const CLIENT: &str = "/api/runner_server.v1.HostClientService";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(&format!("{ENROLL}/StartEnrollment"), post(start))
        .route(&format!("{ENROLL}/PollEnrollment"), post(poll))
        .route(&format!("{ENROLL}/SignOutHost"), post(sign_out))
        .route(&format!("{CLIENT}/ListAccountHosts"), post(list_hosts))
}

pub struct RpcError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl RpcError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
    fn invalid(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "invalid_argument", message)
    }
    fn unauthenticated() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthenticated",
            "Invalid or revoked credential.",
        )
    }
}

impl From<anyhow::Error> for RpcError {
    fn from(e: anyhow::Error) -> Self {
        tracing::error!("rpc failed: {e:#}");
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            "Internal error.",
        )
    }
}

impl IntoResponse for RpcError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(serde_json::json!({ "code": self.code, "message": self.message })),
        )
            .into_response()
    }
}

type RpcResult<T> = Result<Json<T>, RpcError>;

fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T, RpcError> {
    serde_json::from_slice(body).map_err(|_| RpcError::invalid("Malformed request body."))
}

fn clip(value: String, max: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(max)
        .collect()
}

pub fn sanitize(info: HostInfo) -> HostInfo {
    HostInfo {
        hostname: clip(info.hostname, 128),
        platform: clip(info.platform, 32),
        arch: clip(info.arch, 32),
        os_version: clip(info.os_version, 128),
        runner_version: clip(info.runner_version, 64),
    }
}

pub fn rfc3339(ts: i64) -> Option<String> {
    DateTime::from_timestamp(ts, 0).map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true))
}

pub fn decode_host_key(key: &str) -> Option<Vec<u8>> {
    STANDARD.decode(key).ok().filter(|k| k.len() == 32)
}

async fn start(State(state): State<AppState>, body: Bytes) -> RpcResult<StartResponse> {
    let request: StartRequest = parse(&body)?;
    if decode_host_key(&request.host_key).is_none() {
        return Err(RpcError::invalid(
            "hostKey must be a base64 32-byte public key.",
        ));
    }
    let info = sanitize(request.host);
    let host_key = request.host_key;
    let device_code = auth::random_token();
    let device_hash = auth::sha256_hex(&device_code);
    let now = now();
    let user_code = state
        .db
        .call(move |c| {
            if db::pending_enrollments(c, now)? >= MAX_PENDING_ENROLLMENTS {
                return Ok(None);
            }
            for _ in 0..8 {
                let enrollment = db::Enrollment {
                    device_hash: device_hash.clone(),
                    user_code: auth::user_code(),
                    host_key: host_key.clone(),
                    info: info.clone(),
                    state: "pending".into(),
                    user_id: None,
                    expires_at: now + ENROLLMENT_TTL,
                };
                if db::insert_enrollment(c, &enrollment, now)? {
                    return Ok(Some(enrollment.user_code));
                }
            }
            anyhow::bail!("could not allocate a unique user code")
        })
        .await?
        .ok_or_else(|| {
            RpcError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "resource_exhausted",
                "Too many pending enrollments; try again later.",
            )
        })?;
    let origin = &state.config.origin;
    Ok(Json(StartResponse {
        device_code: Secret(device_code),
        verification_uri: format!("{origin}/hosts/add"),
        verification_uri_complete: format!("{origin}/hosts/add?code={user_code}"),
        user_code,
        expires_in: ENROLLMENT_TTL as i32,
        interval: POLL_INTERVAL,
    }))
}

enum Polled {
    State(EnrollmentState),
    Issued {
        host_id: i64,
        credential: String,
        user: db::User,
        claim_expires_at: i64,
        replaced: Vec<i64>,
    },
}

fn state_only(state: EnrollmentState) -> PollResponse {
    PollResponse {
        state,
        ..Default::default()
    }
}

async fn poll(State(state): State<AppState>, body: Bytes) -> RpcResult<PollResponse> {
    let request: PollRequest = parse(&body)?;
    let device_hash = auth::sha256_hex(&request.device_code.0);
    let now = now();
    let polled = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let Some(e) = db::enrollment_by_device(&tx, &device_hash)? else {
                return Ok(Polled::State(EnrollmentState::Expired));
            };
            let result = if e.expires_at <= now {
                db::delete_enrollment(&tx, &device_hash)?;
                Polled::State(EnrollmentState::Expired)
            } else {
                match e.state.as_str() {
                    "approved" => {
                        let user = match e.user_id {
                            Some(id) => db::user_by_id(&tx, id)?.filter(|u| !u.disabled),
                            None => None,
                        };
                        db::delete_enrollment(&tx, &device_hash)?;
                        match user {
                            None => Polled::State(EnrollmentState::Denied),
                            Some(user) => {
                                let replaced = db::host_ids_with_key(&tx, &e.host_key)?;
                                for id in &replaced {
                                    db::delete_host(&tx, *id, None)?;
                                }
                                let host_id = loop {
                                    let id = auth::host_id();
                                    if !db::host_exists(&tx, id)? {
                                        break id;
                                    }
                                };
                                let credential = auth::credential();
                                let key = decode_host_key(&e.host_key).unwrap_or_default();
                                let name = if e.info.hostname.is_empty() {
                                    "Unnamed computer".to_owned()
                                } else {
                                    e.info.hostname.clone()
                                };
                                let claim_expires_at = now + CLAIM_TTL;
                                db::insert_host(
                                    &tx,
                                    &db::NewHost {
                                        id: host_id,
                                        user_id: user.id,
                                        name: &name,
                                        info: &e.info,
                                        host_key: &e.host_key,
                                        fingerprint: &remote::fingerprint(&key),
                                        credential_hash: &auth::sha256_hex(&credential),
                                        claim_expires_at,
                                    },
                                    now,
                                )?;
                                Polled::Issued {
                                    host_id,
                                    credential,
                                    user,
                                    claim_expires_at,
                                    replaced,
                                }
                            }
                        }
                    }
                    "denied" => {
                        db::delete_enrollment(&tx, &device_hash)?;
                        Polled::State(EnrollmentState::Denied)
                    }
                    _ => Polled::State(EnrollmentState::Pending),
                }
            };
            tx.commit()?;
            Ok(result)
        })
        .await?;
    Ok(Json(match polled {
        Polled::State(s) => state_only(s),
        Polled::Issued {
            host_id,
            credential,
            user,
            claim_expires_at,
            replaced,
        } => {
            for id in replaced {
                state.hub.kick(id, relay::CLOSE_REMOVED, "re-enrolled");
            }
            tracing::info!(host = host_id, user = %user.username, "host enrolled");
            PollResponse {
                state: EnrollmentState::Approved,
                host_id: host_id.to_string(),
                credential: Secret(credential),
                relay_url: state.config.relay_url(),
                account: Some(Account {
                    username: user.username,
                    display_name: user.display_name,
                }),
                claim_expires_at: rfc3339(claim_expires_at),
            }
        }
    }))
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(db::Host, db::User), RpcError> {
    let token = auth::bearer(headers).ok_or_else(RpcError::unauthenticated)?;
    let hash = auth::sha256_hex(&token);
    match state
        .db
        .call(move |c| db::host_by_credential(c, &hash))
        .await?
    {
        Some((host, user)) if !user.disabled && host.usable(now()) => Ok((host, user)),
        _ => Err(RpcError::unauthenticated()),
    }
}

#[derive(Serialize)]
struct Empty {}

async fn sign_out(State(state): State<AppState>, headers: HeaderMap) -> RpcResult<Empty> {
    let token = auth::bearer(&headers).ok_or_else(RpcError::unauthenticated)?;
    let hash = auth::sha256_hex(&token);
    let host = state
        .db
        .call(move |c| {
            let found = db::host_by_credential(c, &hash)?;
            if let Some((host, _)) = &found {
                db::delete_host(c, host.id, None)?;
            }
            Ok(found.map(|(h, _)| h.id))
        })
        .await?
        .ok_or_else(RpcError::unauthenticated)?;
    state.hub.kick(host, relay::CLOSE_REMOVED, "signed out");
    tracing::info!(host, "host signed out");
    Ok(Json(Empty {}))
}

#[derive(Serialize)]
struct Hosts {
    hosts: Vec<Computer>,
}

async fn list_hosts(State(state): State<AppState>, headers: HeaderMap) -> RpcResult<Hosts> {
    let (me, user) = authenticate(&state, &headers).await?;
    let hosts = state
        .db
        .call(move |c| db::hosts_for_user(c, user.id))
        .await?;
    Ok(Json(Hosts {
        hosts: hosts
            .into_iter()
            .map(|h| {
                let connected = state.hub.connected_at(h.id);
                Computer {
                    id: h.id.to_string(),
                    name: h.name,
                    info: h.info,
                    fingerprint: h.fingerprint,
                    online: connected.is_some(),
                    connected_at: connected.map(|t| t.to_rfc3339_opts(SecondsFormat::Secs, true)),
                    last_seen_at: h.last_seen_at.and_then(rfc3339),
                    is_self: h.id == me.id,
                    paired: false,
                }
            })
            .collect(),
    }))
}
