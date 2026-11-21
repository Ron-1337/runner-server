use crate::{
    AppState, auth, db, now,
    protocol::{self, Account, CLIENT_SUBPROTOCOL, Control, DeviceKind, MAX_FRAME},
};
use axum::{
    Router,
    body::Bytes,
    extract::{
        Query, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::get,
};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt, stream::SplitSink};
use serde::Deserialize;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::mpsc, time::timeout};

pub const MAX_QUEUED_BYTES: usize = 1024 * 1024;
pub const MAX_CHANNELS_PER_HOST: usize = 64;
const PING_INTERVAL: Duration = Duration::from_secs(25);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub const CLOSE_IN_USE_ELSEWHERE: u16 = 4001;
pub const CLOSE_REMOVED: u16 = 4003;
pub const CLOSE_OVERFLOW: u16 = 4413;
pub const CLOSE_RESTART: u16 = 1012;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/relay/host", get(host_upgrade))
        .route("/relay/client", get(client_upgrade))
}

enum HostOut {
    Text(String),
    Binary(Vec<u8>, Arc<AtomicUsize>),
    Close(u16, &'static str),
}

enum ClientOut {
    Binary(Bytes, Arc<AtomicUsize>),
    Close(u16, &'static str),
}

struct ChannelEntry {
    tx: mpsc::UnboundedSender<ClientOut>,
    to_client: Arc<AtomicUsize>,
    to_host: Arc<AtomicUsize>,
}

struct HostEntry {
    conn: u64,
    tx: mpsc::UnboundedSender<HostOut>,
    connected_at: DateTime<Utc>,
    channels: HashMap<u32, ChannelEntry>,
    next_channel: u32,
}

impl HostEntry {
    fn send_text(&self, control: &Control) {
        if let Ok(text) = serde_json::to_string(control) {
            let _ = self.tx.send(HostOut::Text(text));
        }
    }

    fn close_all(self, code: u16, reason: &'static str) {
        let _ = self.tx.send(HostOut::Close(code, reason));
        for channel in self.channels.into_values() {
            let _ = channel.tx.send(ClientOut::Close(code, reason));
        }
    }

    fn overflow(&mut self, channel: u32) {
        if let Some(entry) = self.channels.remove(&channel) {
            let _ = entry
                .tx
                .send(ClientOut::Close(CLOSE_OVERFLOW, "queue overflow"));
            self.send_text(&Control::ChannelClosed { channel });
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    Offline,
    Busy,
}

struct ClientLink {
    channel: u32,
    conn: u64,
    rx: mpsc::UnboundedReceiver<ClientOut>,
}

#[derive(Default)]
pub struct Hub {
    hosts: Mutex<HashMap<i64, HostEntry>>,
    conns: AtomicU64,
}

fn reserve(counter: &AtomicUsize, len: usize) -> bool {
    let before = counter.fetch_add(len, Ordering::AcqRel);
    if before + len > MAX_QUEUED_BYTES {
        counter.fetch_sub(len, Ordering::AcqRel);
        return false;
    }
    true
}

impl Hub {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<i64, HostEntry>> {
        self.hosts.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn attach_host(&self, id: i64, tx: mpsc::UnboundedSender<HostOut>) -> u64 {
        let conn = self.conns.fetch_add(1, Ordering::Relaxed) + 1;
        let entry = HostEntry {
            conn,
            tx,
            connected_at: Utc::now(),
            channels: HashMap::new(),
            next_channel: 1,
        };
        if let Some(old) = self.lock().insert(id, entry) {
            old.close_all(CLOSE_IN_USE_ELSEWHERE, "in use elsewhere");
        }
        conn
    }

    fn detach_host(&self, id: i64, conn: u64) {
        let mut hosts = self.lock();
        if hosts.get(&id).is_some_and(|h| h.conn == conn) {
            let entry = hosts.remove(&id).expect("checked");
            for channel in entry.channels.into_values() {
                let _ = channel.tx.send(ClientOut::Close(1001, "host disconnected"));
            }
        }
    }

    pub fn kick(&self, id: i64, code: u16, reason: &'static str) {
        if let Some(entry) = self.lock().remove(&id) {
            entry.close_all(code, reason);
        }
    }

    pub fn shutdown(&self) {
        for (_, entry) in self.lock().drain() {
            entry.close_all(CLOSE_RESTART, "service restart");
        }
    }

    pub fn connected_at(&self, id: i64) -> Option<DateTime<Utc>> {
        self.lock().get(&id).map(|h| h.connected_at)
    }

    pub fn can_open(&self, id: i64) -> Result<(), OpenError> {
        match self.lock().get(&id) {
            None => Err(OpenError::Offline),
            Some(h) if h.channels.len() >= MAX_CHANNELS_PER_HOST => Err(OpenError::Busy),
            Some(_) => Ok(()),
        }
    }

    fn open_channel(&self, id: i64) -> Result<ClientLink, OpenError> {
        let mut hosts = self.lock();
        let entry = hosts.get_mut(&id).ok_or(OpenError::Offline)?;
        if entry.channels.len() >= MAX_CHANNELS_PER_HOST {
            return Err(OpenError::Busy);
        }
        let channel = loop {
            let candidate = entry.next_channel;
            entry.next_channel = entry.next_channel.wrapping_add(1).max(1);
            if !entry.channels.contains_key(&candidate) {
                break candidate;
            }
        };
        let (tx, rx) = mpsc::unbounded_channel();
        entry.channels.insert(
            channel,
            ChannelEntry {
                tx,
                to_client: Arc::default(),
                to_host: Arc::default(),
            },
        );
        entry.send_text(&Control::ChannelOpen { channel });
        Ok(ClientLink {
            channel,
            conn: entry.conn,
            rx,
        })
    }

    fn to_client(&self, id: i64, conn: u64, channel: u32, bytes: Bytes) {
        let mut hosts = self.lock();
        let Some(entry) = hosts.get_mut(&id).filter(|h| h.conn == conn) else {
            return;
        };
        let Some(target) = entry.channels.get(&channel) else {
            return;
        };
        if reserve(&target.to_client, bytes.len()) {
            let counter = target.to_client.clone();
            let _ = target.tx.send(ClientOut::Binary(bytes, counter));
        } else {
            entry.overflow(channel);
        }
    }

    fn to_host(&self, id: i64, link: &ClientLink, bytes: &[u8]) -> bool {
        let mut hosts = self.lock();
        let Some(entry) = hosts.get_mut(&id).filter(|h| h.conn == link.conn) else {
            return false;
        };
        let Some(source) = entry.channels.get(&link.channel) else {
            return false;
        };
        if reserve(&source.to_host, bytes.len()) {
            let counter = source.to_host.clone();
            let framed = protocol::wrap(link.channel, bytes);
            let _ = entry.tx.send(HostOut::Binary(framed, counter));
            true
        } else {
            entry.overflow(link.channel);
            false
        }
    }

    fn close_channel(&self, id: i64, conn: u64, channel: u32) {
        let mut hosts = self.lock();
        if let Some(entry) = hosts.get_mut(&id).filter(|h| h.conn == conn)
            && let Some(c) = entry.channels.remove(&channel)
        {
            let _ = c.tx.send(ClientOut::Close(1000, "closed by host"));
        }
    }

    fn client_gone(&self, id: i64, link: &ClientLink) {
        let mut hosts = self.lock();
        if let Some(entry) = hosts.get_mut(&id).filter(|h| h.conn == link.conn)
            && entry.channels.remove(&link.channel).is_some()
        {
            entry.send_text(&Control::ChannelClosed {
                channel: link.channel,
            });
        }
    }
}

fn offers(headers: &HeaderMap, protocol: &str) -> bool {
    headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|p| p.trim() == protocol)
}

async fn authenticate(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(db::Host, db::User), StatusCode> {
    let token = auth::bearer(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    let hash = auth::sha256_hex(&token);
    let found = state
        .db
        .call(move |c| db::host_by_credential(c, &hash))
        .await
        .map_err(|e| {
            tracing::error!("credential lookup failed: {e:#}");
            StatusCode::SERVICE_UNAVAILABLE
        })?;
    match found {
        Some((host, user)) if !user.disabled && host.usable(now()) => Ok((host, user)),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

fn close(code: u16, reason: &'static str) -> Message {
    Message::Close(Some(CloseFrame {
        code,
        reason: reason.into(),
    }))
}

async fn host_upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    if !offers(&headers, protocol::SUBPROTOCOL) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let (host, user) = match authenticate(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return status.into_response(),
    };
    if host.kind != DeviceKind::Computer {
        return StatusCode::FORBIDDEN.into_response();
    }
    ws.protocols([protocol::SUBPROTOCOL])
        .max_message_size(protocol::MAX_RELAY_SIZE)
        .max_frame_size(protocol::MAX_RELAY_SIZE)
        .on_upgrade(move |socket| serve_host(state, socket, host, user))
}

async fn serve_host(state: AppState, socket: WebSocket, host: db::Host, user: db::User) {
    let (mut sink, mut stream) = socket.split();
    let hello = match timeout(HELLO_TIMEOUT, stream.next()).await {
        Ok(Some(Ok(Message::Text(text)))) if text.len() <= protocol::MAX_CONTROL_SIZE => {
            serde_json::from_str::<Control>(&text).ok()
        }
        _ => None,
    };
    let Some(Control::Hello { host: info, .. }) = hello else {
        let _ = sink.send(close(1008, "expected hello")).await;
        return;
    };
    let info = crate::rpc::sanitize(info);
    let id = host.id;
    let activated = state
        .db
        .call(move |c| db::activate_host(c, id, &info, now()))
        .await;
    if !matches!(activated, Ok(true)) {
        let _ = sink.send(close(CLOSE_REMOVED, "removed")).await;
        return;
    }

    let welcome = Control::Welcome {
        host_id: id.to_string(),
        name: host.name.clone(),
        account: Account {
            username: user.username.clone(),
            display_name: user.display_name.clone(),
        },
    };
    let (tx, rx) = mpsc::unbounded_channel();
    let _ = tx.send(HostOut::Text(
        serde_json::to_string(&welcome).expect("welcome serializes"),
    ));
    let conn = state.hub.attach_host(id, tx);
    tracing::info!(host = id, user = %user.username, "host connected");
    let mut writer = tokio::spawn(write_host(sink, rx));

    loop {
        tokio::select! {
            _ = &mut writer => break,
            frame = timeout(IDLE_TIMEOUT, stream.next()) => match frame {
                Ok(Some(Ok(Message::Binary(bytes)))) => {
                    if let Some((channel, _)) = protocol::unwrap(&bytes) {
                        state.hub.to_client(id, conn, channel, bytes.slice(4..));
                    }
                }
                Ok(Some(Ok(Message::Text(text)))) => {
                    if text.len() <= protocol::MAX_CONTROL_SIZE
                        && let Ok(Control::CloseChannel { channel }) = serde_json::from_str(&text) {
                            state.hub.close_channel(id, conn, channel);
                        }
                }
                Ok(Some(Ok(Message::Ping(_) | Message::Pong(_)))) => {}
                _ => break,
            },
        }
    }
    state.hub.detach_host(id, conn);
    tracing::info!(host = id, "host disconnected");
    let _ = state.db.call(move |c| db::touch_host(c, id, now())).await;
}

async fn send(sink: &mut SplitSink<WebSocket, Message>, message: Message) -> bool {
    matches!(timeout(WRITE_TIMEOUT, sink.send(message)).await, Ok(Ok(())))
}

async fn write_host(
    mut sink: SplitSink<WebSocket, Message>,
    mut rx: mpsc::UnboundedReceiver<HostOut>,
) {
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    loop {
        let ok = tokio::select! {
            out = rx.recv() => match out {
                None => break,
                Some(HostOut::Text(text)) => send(&mut sink, Message::Text(text.into())).await,
                Some(HostOut::Binary(bytes, counter)) => {
                    let len = bytes.len() - 4;
                    let ok = send(&mut sink, Message::Binary(bytes.into())).await;
                    counter.fetch_sub(len, Ordering::AcqRel);
                    ok
                }
                Some(HostOut::Close(code, reason)) => {
                    send(&mut sink, close(code, reason)).await;
                    break;
                }
            },
            _ = ping.tick() => send(&mut sink, Message::Ping(Bytes::new())).await,
        };
        if !ok {
            break;
        }
    }
}

#[derive(Deserialize)]
struct ClientQuery {
    host: String,
}

fn refusal(status: StatusCode) -> Response {
    if status == StatusCode::TOO_MANY_REQUESTS {
        return (status, [(header::RETRY_AFTER, "10")]).into_response();
    }
    status.into_response()
}

async fn client_upgrade(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ClientQuery>,
    ws: WebSocketUpgrade,
) -> Response {
    if !offers(&headers, CLIENT_SUBPROTOCOL) {
        return refusal(StatusCode::BAD_REQUEST);
    }
    let (me, user) = match authenticate(&state, &headers).await {
        Ok(found) => found,
        Err(status) => return refusal(status),
    };
    let Ok(target) = query.host.parse::<i64>() else {
        return refusal(StatusCode::NOT_FOUND);
    };
    let host = state.db.call(move |c| db::host_by_id(c, target)).await;
    match host {
        Ok(Some(h)) if h.user_id == user.id && h.activated && h.kind == DeviceKind::Computer => {}
        Ok(_) => return refusal(StatusCode::NOT_FOUND),
        Err(e) => {
            tracing::error!("host lookup failed: {e:#}");
            return refusal(StatusCode::SERVICE_UNAVAILABLE);
        }
    }
    match state.hub.can_open(target) {
        Err(OpenError::Offline) => return refusal(StatusCode::SERVICE_UNAVAILABLE),
        Err(OpenError::Busy) => return refusal(StatusCode::TOO_MANY_REQUESTS),
        Ok(()) => {}
    }
    if me.kind == DeviceKind::Phone {
        // A phone has no host connection to update its last-seen time.
        let id = me.id;
        let _ = state.db.call(move |c| db::touch_host(c, id, now())).await;
    }
    ws.protocols([CLIENT_SUBPROTOCOL])
        .max_message_size(MAX_FRAME)
        .max_frame_size(MAX_FRAME)
        .on_upgrade(move |socket| serve_client(state, socket, target))
}

async fn serve_client(state: AppState, socket: WebSocket, host: i64) {
    let (mut sink, mut stream) = socket.split();
    let mut link = match state.hub.open_channel(host) {
        Ok(link) => link,
        Err(_) => {
            let _ = sink.send(close(1013, "host unavailable")).await;
            return;
        }
    };
    let rx = std::mem::replace(&mut link.rx, mpsc::unbounded_channel().1);
    let mut writer = tokio::spawn(write_client(sink, rx));
    loop {
        tokio::select! {
            _ = &mut writer => break,
            frame = timeout(IDLE_TIMEOUT, stream.next()) => match frame {
                Ok(Some(Ok(Message::Binary(bytes)))) => {
                    if !state.hub.to_host(host, &link, &bytes) {
                        break;
                    }
                }
                Ok(Some(Ok(Message::Text(_) | Message::Ping(_) | Message::Pong(_)))) => {}
                _ => break,
            },
        }
    }
    state.hub.client_gone(host, &link);
}

async fn write_client(
    mut sink: SplitSink<WebSocket, Message>,
    mut rx: mpsc::UnboundedReceiver<ClientOut>,
) {
    let mut ping = tokio::time::interval(PING_INTERVAL);
    ping.tick().await;
    loop {
        let ok = tokio::select! {
            out = rx.recv() => match out {
                None => {
                    send(&mut sink, close(1001, "channel closed")).await;
                    break;
                }
                Some(ClientOut::Binary(bytes, counter)) => {
                    let len = bytes.len();
                    let ok = send(&mut sink, Message::Binary(bytes)).await;
                    counter.fetch_sub(len, Ordering::AcqRel);
                    ok
                }
                Some(ClientOut::Close(code, reason)) => {
                    send(&mut sink, close(code, reason)).await;
                    break;
                }
            },
            _ = ping.tick() => send(&mut sink, Message::Ping(Bytes::new())).await,
        };
        if !ok {
            break;
        }
    }
}
