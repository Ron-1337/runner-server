use crate::protocol::{
    self, Account, Computer, DeviceKind, EnrollmentState, HostInfo, PollRequest, PollResponse,
    Secret, StartRequest, StartResponse,
};
use crate::{AppState, auth, db, notify, now, relay, watch};
use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::{DateTime, SecondsFormat};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub const ENROLLMENT_TTL: i64 = 600;
pub const CLAIM_TTL: i64 = 600;
pub const POLL_INTERVAL: i32 = 5;
const MAX_PENDING_ENROLLMENTS: i64 = 1000;
const ENROLL: &str = "/api/runner_server.v1.HostEnrollmentService";
const CLIENT: &str = "/api/runner_server.v1.HostClientService";
const NOTIFY: &str = "/api/runner_server.v1.NotifyService";

pub fn routes() -> Router<AppState> {
    Router::new()
        .route(&format!("{ENROLL}/StartEnrollment"), post(start))
        .route(&format!("{ENROLL}/PollEnrollment"), post(poll))
        .route(&format!("{ENROLL}/SignOutHost"), post(sign_out))
        .route(&format!("{ENROLL}/SignOutClient"), post(sign_out_client))
        .route(&format!("{CLIENT}/ListAccountHosts"), post(list_hosts))
        .route(&format!("{NOTIFY}/GetSettings"), post(get_settings))
        .route(&format!("{NOTIFY}/SetSettings"), post(set_settings))
        .route(&format!("{NOTIFY}/Test"), post(test_notify))
        .route(&format!("{NOTIFY}/ListWatchers"), post(list_watchers))
        .route(&format!("{NOTIFY}/PairWatcher"), post(pair_watcher))
        .route(&format!("{NOTIFY}/UnpairWatcher"), post(unpair_watcher))
        .route(&format!("{NOTIFY}/ClaimSession"), post(claim_session))
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
    protocol::decode_key(key)
}

async fn start(
    State(state): State<AppState>,
    auth::ClientIp(requesting_ip): auth::ClientIp,
    body: Bytes,
) -> RpcResult<StartResponse> {
    let request: StartRequest = parse(&body)?;
    // The official phone app enrolls as a client without a key: its channels
    // are keyed by pairing with each computer, not by the account.
    let keyless_client = request.kind == DeviceKind::Phone && request.host_key.is_empty();
    if !keyless_client && decode_host_key(&request.host_key).is_none() {
        return Err(RpcError::invalid(
            "hostKey must be a base64 32-byte public key.",
        ));
    }
    let host_key = request.host_key.clone();
    let kind = request.kind;
    let info = sanitize(request.device_info());
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
                    kind,
                    requesting_ip: requesting_ip.clone(),
                    name: String::new(),
                    created_at: now,
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
        kind: DeviceKind,
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
                                let replaced = if e.host_key.is_empty() {
                                    Vec::new()
                                } else {
                                    db::host_ids_with_key(&tx, &e.host_key)?
                                };
                                for id in &replaced {
                                    db::delete_host(&tx, *id, None)?;
                                }
                                let host_id = loop {
                                    let id = auth::host_id();
                                    if !db::host_exists(&tx, id)? {
                                        break id;
                                    }
                                };
                                let credential = match e.kind {
                                    DeviceKind::Phone => auth::client_credential(),
                                    DeviceKind::Computer => auth::credential(),
                                };
                                let key = decode_host_key(&e.host_key).unwrap_or_default();
                                let name = if !e.name.is_empty() {
                                    e.name.clone()
                                } else if e.info.hostname.is_empty() {
                                    match e.kind {
                                        DeviceKind::Computer => "Unnamed computer",
                                        DeviceKind::Phone => "Unnamed phone",
                                    }
                                    .to_owned()
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
                                        fingerprint: &protocol::fingerprint(&key),
                                        credential_hash: &auth::sha256_hex(&credential),
                                        claim_expires_at,
                                        kind: e.kind,
                                    },
                                    now,
                                )?;
                                Polled::Issued {
                                    host_id,
                                    credential,
                                    user,
                                    claim_expires_at,
                                    replaced,
                                    kind: e.kind,
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
            kind,
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
                client_id: match kind {
                    DeviceKind::Phone => host_id.to_string(),
                    DeviceKind::Computer => String::new(),
                },
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

/// The official service's sign-out for phones; only a phone's credential may use it.
async fn sign_out_client(State(state): State<AppState>, headers: HeaderMap) -> RpcResult<Empty> {
    let (me, _) = authenticate(&state, &headers).await?;
    if me.kind != DeviceKind::Phone {
        return Err(RpcError::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "This credential is not a phone's.",
        ));
    }
    let id = me.id;
    state.db.call(move |c| db::delete_host(c, id, None)).await?;
    tracing::info!(host = id, "phone signed out");
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
            .filter(|h| h.kind == DeviceKind::Computer)
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
                }
            })
            .collect(),
    }))
}

// --- NotifyService: a phone's notification settings and the session watchers.

async fn phone(state: &AppState, headers: &HeaderMap) -> Result<(db::Host, db::User), RpcError> {
    let (me, user) = authenticate(state, headers).await?;
    if me.kind != DeviceKind::Phone {
        return Err(RpcError::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "This credential is not a phone's.",
        ));
    }
    Ok((me, user))
}

/// One of [user]'s computers by its id as text.
async fn my_computer(state: &AppState, user: &db::User, id: &str) -> Result<db::Host, RpcError> {
    let not_found = || RpcError::new(StatusCode::NOT_FOUND, "not_found", "找不到这台电脑");
    let id: i64 = id.parse().map_err(|_| not_found())?;
    let user_id = user.id;
    state
        .db
        .call(move |c| db::host_by_id(c, id))
        .await?
        .filter(|h| h.user_id == user_id && h.kind == DeviceKind::Computer && h.activated)
        .ok_or_else(not_found)
}

#[derive(Serialize, Deserialize)]
struct Settings {
    #[serde(default)]
    channel: Option<notify::Channel>,
    #[serde(default)]
    events: notify::Events,
}

async fn get_settings(State(state): State<AppState>, headers: HeaderMap) -> RpcResult<Settings> {
    let (me, _) = phone(&state, &headers).await?;
    let id = me.id;
    let (channel, events) = state.db.call(move |c| db::notify_settings(c, id)).await?;
    Ok(Json(Settings { channel, events }))
}

async fn set_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> RpcResult<Settings> {
    let (me, _) = phone(&state, &headers).await?;
    let request: Settings = parse(&body)?;
    let channel = request
        .channel
        .map(notify::Channel::validate)
        .transpose()
        .map_err(RpcError::invalid)?;
    let (id, events) = (me.id, request.events);
    let saved = channel.clone();
    state
        .db
        .call(move |c| db::set_notify_settings(c, id, saved.as_ref(), &events, now()))
        .await?;
    tracing::info!(
        host = id,
        off = channel.is_none(),
        "notification settings saved"
    );
    Ok(Json(Settings { channel, events }))
}

async fn test_notify(State(state): State<AppState>, headers: HeaderMap) -> RpcResult<Empty> {
    let (me, user) = phone(&state, &headers).await?;
    let id = me.id;
    let Some(channel) = state.db.call(move |c| db::notify_channel(c, id)).await? else {
        return Err(RpcError::invalid("先选择推送方式并保存"));
    };
    let message = notify::test_message(&state.config.origin, &user.username, &me.name);
    state.notifier.send(&channel, &message).await.map_err(|e| {
        RpcError::new(
            StatusCode::BAD_GATEWAY,
            "unavailable",
            format!("发送失败：{e:#}"),
        )
    })?;
    Ok(Json(Empty {}))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct WatcherInfo {
    computer: String,
    name: String,
    online: bool,
    paired: bool,
    watching: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct Watchers {
    watchers: Vec<WatcherInfo>,
}

async fn list_watchers(State(state): State<AppState>, headers: HeaderMap) -> RpcResult<Watchers> {
    let (_, user) = phone(&state, &headers).await?;
    let user_id = user.id;
    let (hosts, paired) = state
        .db
        .call(move |c| Ok((db::hosts_for_user(c, user_id)?, db::watcher_ids(c)?)))
        .await?;
    Ok(Json(Watchers {
        watchers: hosts
            .into_iter()
            .filter(|h| h.kind == DeviceKind::Computer)
            .map(|h| {
                let status = state.watchers.status(h.id).unwrap_or_default();
                WatcherInfo {
                    computer: h.id.to_string(),
                    online: state.hub.connected_at(h.id).is_some(),
                    paired: paired.contains(&h.id),
                    watching: status.watching,
                    error: status.error,
                    name: h.name,
                }
            })
            .collect(),
    }))
}

#[derive(Deserialize)]
struct PairRequest {
    computer: String,
    pin: String,
}

async fn pair_watcher(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> RpcResult<Empty> {
    let (_, user) = phone(&state, &headers).await?;
    let request: PairRequest = parse(&body)?;
    let computer = my_computer(&state, &user, &request.computer).await?;
    watch::pair(&state, user.id, computer.id, request.pin.trim())
        .await
        .map_err(|m| RpcError::new(StatusCode::BAD_REQUEST, "failed_precondition", m))?;
    Ok(Json(Empty {}))
}

#[derive(Deserialize)]
struct ComputerRequest {
    computer: String,
}

async fn unpair_watcher(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> RpcResult<Empty> {
    let (_, user) = phone(&state, &headers).await?;
    let request: ComputerRequest = parse(&body)?;
    let id = my_computer(&state, &user, &request.computer).await?.id;
    state.watchers.stop(id);
    state.db.call(move |c| db::delete_watcher(c, id)).await?;
    tracing::info!(host = id, "watcher unpaired");
    Ok(Json(Empty {}))
}

#[derive(Deserialize)]
struct ClaimRequest {
    computer: String,
    session: String,
}

async fn claim_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> RpcResult<Empty> {
    let (me, user) = phone(&state, &headers).await?;
    let request: ClaimRequest = parse(&body)?;
    let session = request.session.trim().to_owned();
    if session.is_empty() || session.len() > 128 {
        return Err(RpcError::invalid("session is required."));
    }
    let computer = my_computer(&state, &user, &request.computer).await?.id;
    let device = me.id;
    state
        .db
        .call(move |c| {
            db::claim_session(c, computer, &session, device, now())?;
            db::claim_session(c, computer, "", device, now())
        })
        .await?;
    Ok(Json(Empty {}))
}
