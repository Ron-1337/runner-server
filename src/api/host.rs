//! HostService: the signed-in user's computers and phones, who is connected,
//! and approving device sign-ins.

use super::{ApiError, ApiResult, Empty, ErrorCode, Session, de_id, parse, path, ts};
use crate::{
    AppState, auth, db, now,
    protocol::{self, ClientInfo, DeviceKind, HostInfo},
    relay, rpc, web,
};
use axum::{Json, Router, body::Bytes, extract::State, routing::post};
use serde::{Deserialize, Serialize};

pub fn routes() -> Router<AppState> {
    let at = |m| path("HostService", m);
    Router::new()
        .route(&at("ListHosts"), post(list_hosts))
        .route(&at("ListClients"), post(list_clients))
        .route(&at("ListConnections"), post(list_connections))
        .route(&at("RenameHost"), post(rename_host))
        .route(&at("RemoveHost"), post(remove_host))
        .route(&at("RemoveClient"), post(remove_client))
        .route(&at("LookupEnrollment"), post(lookup_enrollment))
        .route(&at("ApproveEnrollment"), post(approve_enrollment))
        .route(&at("DenyEnrollment"), post(deny_enrollment))
}

/// `runner_server.v1.Host`: a computer.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Host {
    id: String,
    name: String,
    info: HostInfo,
    fingerprint: String,
    online: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    connected_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_seen_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

fn host(state: &AppState, h: &db::Host) -> Host {
    let connected = state.hub.connected_at(h.id);
    Host {
        id: h.id.to_string(),
        name: h.name.clone(),
        info: h.info.clone(),
        fingerprint: h.fingerprint.clone(),
        online: connected.is_some(),
        connected_at: connected.and_then(|t| ts(t.timestamp())),
        last_seen_at: h.last_seen_at.and_then(ts),
        created_at: ts(h.created_at),
    }
}

/// `runner_server.v1.Client`: a phone.
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Client {
    id: String,
    name: String,
    info: ClientInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    created_at: Option<String>,
}

fn client(h: &db::Host) -> Client {
    Client {
        id: h.id.to_string(),
        name: h.name.clone(),
        info: ClientInfo::from_host_info(&h.info),
        created_at: ts(h.created_at),
    }
}

async fn my_devices(state: &AppState, user_id: i64) -> anyhow::Result<Vec<db::Host>> {
    state.db.call(move |c| db::hosts_for_user(c, user_id)).await
}

#[derive(Serialize)]
struct ListHostsResponse {
    hosts: Vec<Host>,
}

async fn list_hosts(
    State(state): State<AppState>,
    Session(me): Session,
) -> ApiResult<ListHostsResponse> {
    let devices = my_devices(&state, me.user.id).await?;
    Ok(Json(ListHostsResponse {
        hosts: devices
            .iter()
            .filter(|h| h.kind == DeviceKind::Computer)
            .map(|h| host(&state, h))
            .collect(),
    }))
}

#[derive(Serialize)]
struct ListClientsResponse {
    clients: Vec<Client>,
}

async fn list_clients(
    State(state): State<AppState>,
    Session(me): Session,
) -> ApiResult<ListClientsResponse> {
    let devices = my_devices(&state, me.user.id).await?;
    Ok(Json(ListClientsResponse {
        clients: devices
            .iter()
            .filter(|h| h.kind == DeviceKind::Phone)
            .map(client)
            .collect(),
    }))
}

/// `runner_server.v1.Connection`: [host] is the computer being used, and
/// [computer] or [phone] the device using it.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Connection {
    host: Host,
    #[serde(skip_serializing_if = "Option::is_none")]
    computer: Option<Host>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<Client>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connected_at: Option<String>,
}

#[derive(Serialize)]
struct ListConnectionsResponse {
    connections: Vec<Connection>,
}

async fn list_connections(
    State(state): State<AppState>,
    Session(me): Session,
) -> ApiResult<ListConnectionsResponse> {
    let devices = my_devices(&state, me.user.id).await?;
    let computers: Vec<i64> = devices
        .iter()
        .filter(|h| h.kind == DeviceKind::Computer)
        .map(|h| h.id)
        .collect();
    let find = |id: i64| devices.iter().find(|h| h.id == id);
    let connections = state
        .hub
        .connections(&computers)
        .into_iter()
        .filter_map(|c| {
            let target = find(c.host)?;
            let opener = find(c.device)?;
            let phone = opener.kind == DeviceKind::Phone;
            Some(Connection {
                host: host(&state, target),
                computer: (!phone).then(|| host(&state, opener)),
                phone: phone.then(|| client(opener)),
                connected_at: ts(c.since.timestamp()),
            })
        })
        .collect();
    Ok(Json(ListConnectionsResponse { connections }))
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RenameHostRequest {
    #[serde(alias = "host_id", deserialize_with = "de_id")]
    host_id: i64,
    name: String,
}

fn host_not_found() -> ApiError {
    ApiError::not_found("No such device.", ErrorCode::HostNotFound)
}

/// Renames a computer or a phone.
async fn rename_host(
    State(state): State<AppState>,
    Session(me): Session,
    body: Bytes,
) -> ApiResult<Empty> {
    let request: RenameHostRequest = parse(&body)?;
    let name = web::clean_host_name(&request.name)
        .ok_or_else(|| ApiError::invalid("A name is 1–64 characters."))?;
    let (id, user_id) = (request.host_id, me.user.id);
    if !state
        .db
        .call(move |c| db::rename_host(c, id, user_id, &name))
        .await?
    {
        return Err(host_not_found());
    }
    tracing::info!(host = id, "device renamed");
    Ok(Json(Empty {}))
}

/// Removes one of the user's devices of [kind] and disconnects it.
async fn remove(state: &AppState, user_id: i64, id: i64, kind: DeviceKind) -> Result<(), ApiError> {
    let removed = state
        .db
        .call(move |c| {
            let tx = c.transaction()?;
            let ok = match db::host_by_id(&tx, id)? {
                Some(h) if h.user_id == user_id && h.kind == kind => {
                    db::delete_host(&tx, id, Some(user_id))?
                }
                _ => false,
            };
            tx.commit()?;
            Ok(ok)
        })
        .await?;
    if !removed {
        return Err(host_not_found());
    }
    state.hub.kick(id, relay::CLOSE_REMOVED, "removed");
    tracing::info!(host = id, kind = kind.as_str(), "device removed");
    Ok(())
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RemoveHostRequest {
    #[serde(alias = "host_id", deserialize_with = "de_id")]
    host_id: i64,
}

async fn remove_host(
    State(state): State<AppState>,
    Session(me): Session,
    body: Bytes,
) -> ApiResult<Empty> {
    let request: RemoveHostRequest = parse(&body)?;
    remove(&state, me.user.id, request.host_id, DeviceKind::Computer).await?;
    Ok(Json(Empty {}))
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RemoveClientRequest {
    #[serde(alias = "client_id", deserialize_with = "de_id")]
    client_id: i64,
}

async fn remove_client(
    State(state): State<AppState>,
    Session(me): Session,
    body: Bytes,
) -> ApiResult<Empty> {
    let request: RemoveClientRequest = parse(&body)?;
    remove(&state, me.user.id, request.client_id, DeviceKind::Phone).await?;
    Ok(Json(Empty {}))
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct CodeRequest {
    #[serde(alias = "user_code")]
    user_code: String,
    name: String,
}

/// `runner_server.v1.Enrollment`: a pending sign-in, with [info] for a computer
/// or [client] for a phone.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Enrollment {
    user_code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<HostInfo>,
    fingerprint: String,
    requesting_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    requested_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    client: Option<ClientInfo>,
}

#[derive(Serialize)]
struct LookupEnrollmentResponse {
    enrollment: Enrollment,
}

fn enrollment_not_found() -> ApiError {
    ApiError::not_found(
        "The code is wrong, used or expired. Start the sign-in again on the device.",
        ErrorCode::EnrollmentNotFound,
    )
}

fn code(raw: &str) -> Result<String, ApiError> {
    auth::normalize_user_code(raw).ok_or_else(enrollment_not_found)
}

async fn lookup_enrollment(
    State(state): State<AppState>,
    Session(_): Session,
    body: Bytes,
) -> ApiResult<LookupEnrollmentResponse> {
    let request: CodeRequest = parse(&body)?;
    let code = code(&request.user_code)?;
    let found = state
        .db
        .call(move |c| db::enrollment_by_code(c, &code))
        .await?;
    let now = now();
    let e = found
        .filter(|e| e.state == "pending" && e.expires_at > now)
        .ok_or_else(enrollment_not_found)?;
    let fingerprint = rpc::decode_host_key(&e.host_key)
        .map(|k| protocol::fingerprint(&k))
        .unwrap_or_default();
    let phone = e.kind == DeviceKind::Phone;
    Ok(Json(LookupEnrollmentResponse {
        enrollment: Enrollment {
            user_code: e.user_code,
            client: phone.then(|| ClientInfo::from_host_info(&e.info)),
            info: (!phone).then_some(e.info),
            fingerprint,
            requesting_ip: e.requesting_ip,
            requested_at: ts(e.created_at),
            expires_at: ts(e.expires_at),
            kind: if phone {
                "ENROLLMENT_KIND_CLIENT"
            } else {
                "ENROLLMENT_KIND_HOST"
            },
        },
    }))
}

async fn decide(
    state: &AppState,
    user_id: i64,
    request: CodeRequest,
    approve: bool,
) -> ApiResult<Empty> {
    let code = code(&request.user_code)?;
    let name = if approve && !request.name.trim().is_empty() {
        Some(
            web::clean_host_name(&request.name)
                .ok_or_else(|| ApiError::invalid("A name is 1–64 characters."))?,
        )
    } else {
        None
    };
    let decided = state
        .db
        .call(move |c| db::decide_enrollment(c, &code, approve, user_id, name.as_deref(), now()))
        .await?;
    if !decided {
        return Err(enrollment_not_found());
    }
    Ok(Json(Empty {}))
}

/// Approves a sign-in for the user's account, optionally naming the device.
async fn approve_enrollment(
    State(state): State<AppState>,
    Session(me): Session,
    body: Bytes,
) -> ApiResult<Empty> {
    decide(&state, me.user.id, parse(&body)?, true).await
}

async fn deny_enrollment(
    State(state): State<AppState>,
    Session(me): Session,
    body: Bytes,
) -> ApiResult<Empty> {
    decide(&state, me.user.id, parse(&body)?, false).await
}
