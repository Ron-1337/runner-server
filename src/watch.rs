//! The service's own read-only watch over a computer's sessions.
//!
//! Runner's companion channel is end-to-end encrypted, so this service cannot
//! read what flows between a phone and a computer. Instead it pairs with the
//! computer as a device of its own ("Runner Remote 通知服务") by the computer's
//! PIN, and keeps a channel open while the computer is online. On it the
//! service only says `hello`, asks for the `overview` and pings; it never sends
//! input or takes control. When a session's status changes to needing input,
//! finished or failed, it notifies the phone that last took the session over,
//! or else the phone that last connected to the computer.

use crate::{AppState, db, notify, protocol::DeviceKind, relay::WatchLink};
use base64::{Engine, engine::general_purpose::STANDARD};
use runner_core::{
    companion::channel::{self, BrowserConnect, BrowserPair, Kind, NoiseKeys, Records, Reject},
    remote::{HostKey, fingerprint, validate_pin_format},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::task::AbortHandle;

/// The name the computer lists this service under among its paired devices.
pub const DEVICE_NAME: &str = "Runner Remote 通知服务";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
/// Under the app's 20 s request timeout, so the phone hears why pairing failed.
const PAIR_TIMEOUT: Duration = Duration::from_secs(15);
const PING_INTERVAL: Duration = Duration::from_secs(20);
const OFFLINE_POLL: Duration = Duration::from_secs(5);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const OVERVIEW_ID: u64 = 1;
/// At most this many notifications per computer per minute.
const MAX_PER_MINUTE: u32 = 30;

/// What a watcher is doing, for the app's list.
#[derive(Clone, Debug, Default)]
pub struct WatchStatus {
    pub watching: bool,
    pub error: Option<String>,
}

struct Task {
    abort: AbortHandle,
    status: Arc<Mutex<WatchStatus>>,
}

#[derive(Default)]
pub struct Watchers {
    tasks: Mutex<HashMap<i64, Task>>,
}

impl Watchers {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<i64, Task>> {
        self.tasks.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn status(&self, computer: i64) -> Option<WatchStatus> {
        self.lock()
            .get(&computer)
            .map(|t| t.status.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    pub fn stop(&self, computer: i64) {
        if let Some(task) = self.lock().remove(&computer) {
            task.abort.abort();
        }
    }

    pub fn shutdown(&self) {
        for (_, task) in self.lock().drain() {
            task.abort.abort();
        }
    }
}

/// Starts watching every paired computer; called once at startup.
pub async fn start_all(state: &AppState) {
    match state.db.call(|c| db::watcher_ids(c)).await {
        Ok(ids) => {
            for id in ids {
                start(state, id);
            }
        }
        Err(e) => tracing::warn!("could not load watchers: {e:#}"),
    }
}

/// (Re)starts the watch over [computer].
pub fn start(state: &AppState, computer: i64) {
    let status = Arc::new(Mutex::new(WatchStatus::default()));
    let task = tokio::spawn(run(state.clone(), computer, status.clone()));
    let old = state.watchers.lock().insert(
        computer,
        Task {
            abort: task.abort_handle(),
            status,
        },
    );
    if let Some(old) = old {
        old.abort.abort();
    }
}

fn set(status: &Mutex<WatchStatus>, watching: bool, error: Option<String>) {
    *status.lock().unwrap_or_else(|e| e.into_inner()) = WatchStatus { watching, error };
}

async fn run(state: AppState, computer: i64, status: Arc<Mutex<WatchStatus>>) {
    let mut backoff = OFFLINE_POLL;
    loop {
        let found = state
            .db
            .call(move |c| {
                let Some(watcher) = db::watcher(c, computer)? else {
                    return Ok(None);
                };
                let Some(host) = db::host_by_id(c, computer)? else {
                    return Ok(None);
                };
                let user = db::user_by_id(c, host.user_id)?;
                Ok(user.map(|u| (watcher, host, u)))
            })
            .await;
        let (watcher, host, user) = match found {
            Ok(Some(found)) => found,
            Ok(None) => {
                state.watchers.lock().remove(&computer);
                return;
            }
            Err(e) => {
                tracing::warn!(host = computer, "watcher lookup failed: {e:#}");
                tokio::time::sleep(MAX_BACKOFF).await;
                continue;
            }
        };
        if user.disabled || state.hub.connected_at(computer).is_none() {
            set(&status, false, None);
            tokio::time::sleep(OFFLINE_POLL).await;
            continue;
        }
        let context = Watch {
            state: state.clone(),
            computer: host.id,
            computer_name: host.name,
            user_id: user.id,
            username: user.username,
            status: status.clone(),
        };
        match context.watch(&watcher).await {
            Ok(()) => {
                set(&status, false, None);
                backoff = OFFLINE_POLL;
            }
            Err(e) => {
                tracing::info!(host = computer, "watch ended: {e}");
                set(&status, false, Some(e));
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
        tokio::time::sleep(backoff).await;
    }
}

fn reject_message(reason: &str) -> String {
    match reason {
        "noPin" => "这台电脑还没有设置 PIN，请先在电脑上运行 runner remote pin".into(),
        "pinLocked" => "PIN 输错次数过多已锁定，请在电脑上重新设置 PIN".into(),
        "wrongPin" => "PIN 不正确".into(),
        "unknownDevice" => "电脑不再信任通知服务（配对可能已被撤销），请重新配对".into(),
        "busy" => "电脑正忙，请稍后再试".into(),
        _ => "握手失败".into(),
    }
}

fn bad(reject: Reject) -> String {
    reject_message(reject.reason())
}

/// One open channel to a computer, with its encryption.
struct Link<'a> {
    state: &'a AppState,
    link: WatchLink,
}

impl Link<'_> {
    fn send(&self, bytes: &[u8]) -> Result<(), String> {
        if self.state.hub.watch_send(&self.link, bytes) {
            Ok(())
        } else {
            Err("连接已断开".into())
        }
    }

    async fn read(&mut self) -> Result<Vec<u8>, String> {
        let bytes = self
            .link
            .recv()
            .await
            .ok_or_else(|| "电脑关闭了连接".to_owned())?;
        if let Ok(reason) = channel::body(&bytes, Kind::Reject) {
            return Err(reject_message(std::str::from_utf8(reason).unwrap_or("")));
        }
        Ok(bytes.to_vec())
    }

    fn flush(&self, records: &mut Records) -> Result<(), String> {
        while let Some(frame) = records.next_frame().map_err(bad)? {
            self.send(&frame)?;
        }
        Ok(())
    }

    /// Says hello and waits for the computer's welcome.
    async fn welcome(&mut self, records: &mut Records) -> Result<Value, String> {
        let hello = json!({
            "type": "hello",
            "versions": [1],
            "client": "runner-server",
            "build": env!("CARGO_PKG_VERSION"),
        });
        records
            .queue(serde_json::to_vec(&hello).expect("hello encodes"))
            .map_err(bad)?;
        loop {
            self.flush(records)?;
            let frame = self.read().await?;
            if let Some(bytes) = records.receive(&frame).map_err(bad)? {
                records.handled();
                self.flush(records)?;
                let message: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                return match message["type"].as_str() {
                    Some("welcome") if message["version"] == 1 => Ok(message),
                    _ => Err("电脑返回了无法识别的欢迎消息".into()),
                };
            }
        }
    }
}

impl Drop for Link<'_> {
    fn drop(&mut self) {
        self.state.hub.watch_close(&self.link);
    }
}

fn open<'a>(state: &'a AppState, computer: i64) -> Result<Link<'a>, String> {
    let link = state
        .hub
        .open_watch(computer)
        .map_err(|_| "这台电脑不在线".to_owned())?;
    Ok(Link { state, link })
}

/// Pairs the service with [computer] of [user_id] by the PIN its owner read off
/// the computer, then starts watching it.
pub async fn pair(state: &AppState, user_id: i64, computer: i64, pin: &str) -> Result<(), String> {
    if validate_pin_format(pin).is_err() {
        return Err("PIN 必须是 6 位数字".into());
    }
    let host = state
        .db
        .call(move |c| db::host_by_id(c, computer))
        .await
        .map_err(|_| "服务器出错，请稍后再试".to_owned())?
        .filter(|h| h.user_id == user_id && h.kind == DeviceKind::Computer && h.activated)
        .ok_or_else(|| "找不到这台电脑".to_owned())?;
    let mut link = open(state, computer)?;
    let key = HostKey::generate().map_err(|_| "无法生成密钥".to_owned())?;
    let host_public = tokio::time::timeout(PAIR_TIMEOUT, async {
        let keys = NoiseKeys {
            private: &key.private,
            fixed_ephemeral: None,
        };
        let (pair, first) =
            BrowserPair::start(keys, pin, rand::random(), rand::random()).map_err(bad)?;
        link.send(&first)?;
        let reply = link.read().await?;
        let (transport, finish, host_public) = pair.finish(&reply, DEVICE_NAME).map_err(bad)?;
        link.send(&finish)?;
        let mut records = Records::new(transport);
        link.welcome(&mut records).await?;
        Ok::<_, String>(host_public)
    })
    .await
    .map_err(|_| "配对超时，请重试".to_owned())??;
    drop(link);
    if fingerprint(&host_public) != host.fingerprint {
        return Err("电脑的指纹与服务器登记的不一致，已中止配对".into());
    }
    let watcher = db::Watcher {
        computer,
        client_private: STANDARD.encode(&*key.private),
        host_public: STANDARD.encode(&host_public),
    };
    state
        .db
        .call(move |c| db::set_watcher(c, &watcher, crate::now()))
        .await
        .map_err(|_| "服务器出错，请稍后再试".to_owned())?;
    tracing::info!(host = computer, "watcher paired");
    start(state, computer);
    Ok(())
}

/// What the watcher knows of one session.
struct Seen {
    kind: String,
    title: String,
    status: String,
}

struct Watch {
    state: AppState,
    computer: i64,
    computer_name: String,
    user_id: i64,
    username: String,
    status: Arc<Mutex<WatchStatus>>,
}

impl Watch {
    async fn watch(&self, watcher: &db::Watcher) -> Result<(), String> {
        let key = HostKey::from_private(&watcher.client_private)
            .map_err(|_| "保存的密钥已损坏，请重新配对".to_owned())?;
        let host = STANDARD
            .decode(&watcher.host_public)
            .map_err(|_| "保存的电脑密钥已损坏，请重新配对".to_owned())?;
        let mut link = open(&self.state, self.computer)?;
        let (mut records, welcome) = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
            let keys = NoiseKeys {
                private: &key.private,
                fixed_ephemeral: None,
            };
            let (connect, first) = BrowserConnect::start(keys, &host).map_err(bad)?;
            link.send(&first)?;
            let reply = link.read().await?;
            let mut records = Records::new(connect.accept(&reply).map_err(bad)?);
            let welcome = link.welcome(&mut records).await?;
            Ok::<_, String>((records, welcome))
        })
        .await
        .map_err(|_| "连接超时".to_owned())??;
        let pings = welcome["features"]
            .as_array()
            .is_some_and(|f| f.iter().any(|f| f == "ping"));
        set(&self.status, true, None);
        tracing::info!(host = self.computer, "watching sessions");

        let mut outgoing =
            VecDeque::from([
                serde_json::to_vec(&json!({"type": "overview", "id": OVERVIEW_ID}))
                    .expect("request encodes"),
            ]);
        let mut next_id = OVERVIEW_ID + 1;
        let mut sessions: Option<HashMap<String, Seen>> = None;
        let mut limit = Limit::default();
        let mut ping = tokio::time::interval(PING_INTERVAL);
        ping.tick().await;
        loop {
            while !records.sending()
                && let Some(message) = outgoing.pop_front()
            {
                records.queue(message).map_err(bad)?;
            }
            link.flush(&mut records)?;
            tokio::select! {
                frame = link.read() => {
                    let frame = frame?;
                    let Some(bytes) = records.receive(&frame).map_err(bad)? else {
                        continue;
                    };
                    records.handled();
                    let message: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                    for (session, event) in observe(&mut sessions, &message) {
                        if limit.allow() {
                            self.notify(session, event).await;
                        } else {
                            tracing::warn!(host = self.computer, "notification dropped: rate limit");
                        }
                    }
                }
                _ = ping.tick(), if pings => {
                    outgoing.push_back(
                        serde_json::to_vec(&json!({"type": "ping", "id": next_id}))
                            .expect("ping encodes"),
                    );
                    next_id += 1;
                }
            }
        }
    }

    async fn notify(&self, (session, title): (String, String), event: notify::Event) {
        let (computer, claimed) = (self.computer, session.clone());
        let owner = self
            .state
            .db
            .call(move |c| db::session_owner(c, computer, &claimed))
            .await;
        let device = match owner {
            Ok(Some(device)) => device,
            Ok(None) => {
                tracing::debug!(host = computer, "no phone to notify");
                return;
            }
            Err(e) => {
                tracing::warn!(host = computer, "notify target lookup failed: {e:#}");
                return;
            }
        };
        let message = notify::Message {
            title: notify::TITLE.into(),
            body: format!("[{}]:{}", event.label(), title),
            url: Some(notify::app_link(
                &self.state.config.origin,
                &self.username,
                Some((computer, Some(&session))),
            )),
            context: notify::Context {
                event: event.key().into(),
                computer: computer.to_string(),
                computer_name: self.computer_name.clone(),
                session,
                session_title: title,
            },
        };
        let (state, user_id) = (self.state.clone(), self.user_id);
        tokio::spawn(async move {
            match notify::deliver(&state, user_id, device, Some(event), message).await {
                Ok(true) => tracing::info!(host = computer, device, "session notification sent"),
                Ok(false) => tracing::debug!(host = computer, device, "notification not wanted"),
                Err(e) => tracing::warn!(host = computer, device, "notification failed: {e:#}"),
            }
        });
    }
}

#[derive(Default)]
struct Limit {
    window: Option<tokio::time::Instant>,
    count: u32,
}

impl Limit {
    fn allow(&mut self) -> bool {
        let now = tokio::time::Instant::now();
        if self
            .window
            .is_none_or(|start| now.duration_since(start) >= Duration::from_secs(60))
        {
            self.window = Some(now);
            self.count = 0;
        }
        self.count += 1;
        self.count <= MAX_PER_MINUTE
    }
}

/// The event a session's change of status is worth, as Runner's own
/// notifications: missions' agents never notify for finishing, shells never.
fn event(kind: &str, before: Option<&str>, after: &str) -> Option<notify::Event> {
    if kind == "shell" || before == Some(after) {
        return None;
    }
    match after {
        "needsYou" => Some(notify::Event::Input),
        "error" => Some(notify::Event::Failed),
        "idle" if before == Some("working") && kind == "chat" => Some(notify::Event::Finished),
        _ => None,
    }
}

type Noticed = Vec<((String, String), notify::Event)>;

/// Applies one message from the computer and returns the events it brings.
/// The first overview is the baseline and brings none.
fn observe(sessions: &mut Option<HashMap<String, Seen>>, message: &Value) -> Noticed {
    let mut out = Vec::new();
    match message["type"].as_str() {
        Some("result") if message["id"] == OVERVIEW_ID && sessions.is_none() => {
            let mut seen = HashMap::new();
            if let Some(list) = message["result"]["sessions"].as_object() {
                for (id, s) in list {
                    seen.insert(id.clone(), seen_from(s));
                }
            }
            *sessions = Some(seen);
        }
        Some("overview") => {
            let Some(seen) = sessions.as_mut() else {
                return out;
            };
            let Some(list) = message["sessions"].as_object() else {
                return out;
            };
            seen.retain(|id, _| list.contains_key(id));
            for (id, s) in list {
                let next = seen_from(s);
                let before = seen.get(id).map(|old| old.status.clone());
                if let Some(e) = event(&next.kind, before.as_deref(), &next.status) {
                    out.push(((id.clone(), next.title.clone()), e));
                }
                seen.insert(id.clone(), next);
            }
        }
        Some("status") => {
            let Some(seen) = sessions.as_mut() else {
                return out;
            };
            let (Some(id), Some(after)) = (message["session"].as_str(), message["status"].as_str())
            else {
                return out;
            };
            let entry = seen.entry(id.to_owned()).or_insert_with(|| Seen {
                kind: "chat".into(),
                title: String::new(),
                status: String::new(),
            });
            let before = (!entry.status.is_empty()).then(|| entry.status.clone());
            if let Some(e) = event(&entry.kind, before.as_deref(), after) {
                let title = if entry.title.is_empty() {
                    "会话".to_owned()
                } else {
                    entry.title.clone()
                };
                out.push(((id.to_owned(), title), e));
            }
            entry.status = after.to_owned();
        }
        _ => {}
    }
    out
}

fn seen_from(session: &Value) -> Seen {
    let text = |key: &str| session[key].as_str().unwrap_or_default().to_owned();
    Seen {
        kind: text("kind"),
        title: text("title"),
        status: text("status"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::Event;

    fn session(kind: &str, title: &str, status: &str) -> Value {
        json!({"kind": kind, "title": title, "status": status, "reason": null, "unread": false})
    }

    #[test]
    fn status_changes_notify_as_runner_does() {
        let mut seen = None;
        // Statuses before the first overview are ignored.
        let early = json!({"type": "status", "session": "a", "status": "needsYou"});
        assert!(observe(&mut seen, &early).is_empty());
        let overview = json!({"type": "result", "id": OVERVIEW_ID, "result": {"sessions": {
            "a": session("chat", "Fix login", "working"),
            "m": session("agent", "coder", "working"),
            "s": session("shell", "zsh", "working"),
        }}});
        assert!(observe(&mut seen, &overview).is_empty());

        let status =
            |id: &str, status: &str| json!({"type": "status", "session": id, "status": status});
        let got = |seen: &mut _, m| -> Vec<(String, Event)> {
            observe(seen, &m)
                .into_iter()
                .map(|((_, t), e)| (t, e))
                .collect()
        };
        assert_eq!(
            got(&mut seen, status("a", "needsYou")),
            [("Fix login".into(), Event::Input)]
        );
        assert!(got(&mut seen, status("a", "needsYou")).is_empty());
        assert!(got(&mut seen, status("a", "working")).is_empty());
        assert_eq!(
            got(&mut seen, status("a", "idle")),
            [("Fix login".into(), Event::Finished)]
        );
        // A mission's agent does not notify for finishing; a shell never.
        assert!(got(&mut seen, status("m", "idle")).is_empty());
        assert!(got(&mut seen, status("s", "error")).is_empty());
        assert_eq!(
            got(&mut seen, status("m", "error")),
            [("coder".into(), Event::Failed)]
        );

        // An overview push brings changes too, and new sessions with their title.
        let pushed = json!({"type": "overview", "sessions": {
            "a": session("chat", "Fix login", "error"),
            "b": session("chat", "New", "needsYou"),
        }});
        assert_eq!(
            got(&mut seen, pushed),
            [
                ("Fix login".into(), Event::Failed),
                ("New".into(), Event::Input)
            ]
        );
    }
}
