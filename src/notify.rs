//! Notifications to phones through third-party push services.
//!
//! A phone has no connection to this service while the app is in the
//! background, so a computer asks the service to push for it: the computer
//! sends a `notify` control message on `/relay/host` naming the phone, and the
//! service delivers it through the channel configured for that phone on the
//! web page. Channels: Bark (iOS), ntfy and a generic webhook.
//!
//! The service also watches computers itself (`watch.rs`) and pushes when a
//! session needs input, finishes or fails.

use crate::{AppState, db, protocol::DeviceKind};
use anyhow::{Context as _, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_BARK_SERVER: &str = "https://api.day.app";
pub const DEFAULT_NTFY_SERVER: &str = "https://ntfy.sh";
/// The title of every session notification.
pub const TITLE: &str = "Runner Remote";
const TIMEOUT: Duration = Duration::from_secs(10);
/// Longest title and body pushed; longer text is cut.
const MAX_TITLE: usize = 120;
const MAX_BODY: usize = 1000;
const MAX_URL: usize = 2048;

/// How notifications reach one phone.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Channel {
    Bark(Bark),
    Ntfy(Ntfy),
    Webhook(Webhook),
}

impl Channel {
    pub fn validate(self) -> Result<Self, &'static str> {
        Ok(match self {
            Self::Bark(b) => Self::Bark(b.validate()?),
            Self::Ntfy(n) => Self::Ntfy(n.validate()?),
            Self::Webhook(w) => Self::Webhook(w.validate()?),
        })
    }
}

/// Which session events a phone wants, as Runner's chat notifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Events {
    pub input: bool,
    pub finished: bool,
    pub failed: bool,
}

impl Default for Events {
    fn default() -> Self {
        Self {
            input: true,
            finished: true,
            failed: true,
        }
    }
}

/// A session event the watcher noticed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Input,
    Finished,
    Failed,
}

impl Event {
    pub fn label(self) -> &'static str {
        match self {
            Self::Input => "需要输入",
            Self::Finished => "已完成",
            Self::Failed => "失败",
        }
    }
    pub fn key(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Finished => "finished",
            Self::Failed => "failed",
        }
    }
    pub fn wanted(self, events: &Events) -> bool {
        match self {
            Self::Input => events.input,
            Self::Finished => events.finished,
            Self::Failed => events.failed,
        }
    }
}

fn http_url(text: &str) -> bool {
    matches!(url::Url::parse(text), Ok(u) if matches!(u.scheme(), "https" | "http") && u.host_str().is_some())
}

/// [ntfy](https://ntfy.sh): JSON publish to the server root.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Ntfy {
    pub server: String,
    pub topic: String,
    /// An access token for a protected topic; empty for none.
    pub token: String,
    /// 1–5; 0 for the server's default.
    pub priority: u8,
    /// Comma-separated tags or emoji short codes.
    pub tags: String,
}

impl Ntfy {
    pub fn validate(mut self) -> Result<Self, &'static str> {
        self.server = self.server.trim().trim_end_matches('/').to_owned();
        if self.server.is_empty() {
            self.server = DEFAULT_NTFY_SERVER.to_owned();
        }
        if !http_url(&self.server) {
            return Err("ntfy 服务器地址无效，例如 https://ntfy.sh");
        }
        self.topic = self.topic.trim().to_owned();
        if self.topic.is_empty()
            || self.topic.len() > 64
            || !self
                .topic
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("ntfy 主题无效：只含字母、数字、- 和 _，最长 64 个字符");
        }
        self.token = clip(self.token.trim(), 256);
        if self.priority > 5 {
            return Err("ntfy 优先级应为 1 到 5");
        }
        self.tags = clip(self.tags.trim(), 128);
        Ok(self)
    }
}

/// Any other service: an HTTP POST of JSON, or of the person's own template.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Webhook {
    pub url: String,
    pub headers: std::collections::BTreeMap<String, String>,
    /// The request body with `{{title}}`-style placeholders; empty for the
    /// default JSON.
    pub template: String,
    /// `{{group}}`; empty for "Runner Remote".
    pub group: String,
}

const MAX_HEADERS: usize = 16;
const MAX_TEMPLATE: usize = 4000;

impl Webhook {
    pub fn validate(mut self) -> Result<Self, &'static str> {
        self.url = self.url.trim().to_owned();
        if self.url.len() > MAX_URL || !http_url(&self.url) {
            return Err("Webhook 地址无效，须以 http:// 或 https:// 开头");
        }
        if self.headers.len() > MAX_HEADERS {
            return Err("请求头太多");
        }
        let mut headers = std::collections::BTreeMap::new();
        for (name, value) in self.headers {
            let name = name.trim().to_owned();
            let value = value.trim().to_owned();
            if reqwest::header::HeaderName::from_bytes(name.as_bytes()).is_err()
                || reqwest::header::HeaderValue::from_str(&value).is_err()
                || name.len() > 128
                || value.len() > 1024
            {
                return Err("请求头无效：每行写成 名称: 值");
            }
            headers.insert(name, value);
        }
        self.headers = headers;
        if self.template.chars().count() > MAX_TEMPLATE {
            return Err("消息模板太长");
        }
        self.group = clip(self.group.trim(), 64);
        Ok(self)
    }
}

/// [Bark](https://github.com/Finb/Bark): `POST <server>/push` with the device key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Bark {
    /// `https://api.day.app`, or a self-hosted bark-server.
    pub server: String,
    pub device_key: String,
    /// Groups the notifications in Notification Center.
    pub group: String,
    pub sound: String,
    /// `active`, `timeSensitive`, `passive` or `critical`; empty for Bark's default.
    pub level: String,
}

pub const BARK_LEVELS: &[(&str, &str)] = &[
    ("", "默认"),
    ("active", "普通（active）"),
    ("timeSensitive", "时效性通知（timeSensitive）"),
    ("passive", "静默（passive）"),
    ("critical", "重要警告（critical）"),
];

impl Bark {
    /// Checks and tidies the settings from the web form.
    pub fn validate(mut self) -> Result<Self, &'static str> {
        self.server = self.server.trim().trim_end_matches('/').to_owned();
        if self.server.is_empty() {
            self.server = DEFAULT_BARK_SERVER.to_owned();
        }
        match url::Url::parse(&self.server) {
            Ok(u) if matches!(u.scheme(), "https" | "http") && u.host_str().is_some() => {}
            _ => return Err("Bark 服务器地址无效，例如 https://api.day.app"),
        }
        self.device_key = self.device_key.trim().to_owned();
        if self.device_key.is_empty()
            || self.device_key.len() > 128
            || !self
                .device_key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err("Device Key 无效：在 Bark App 中复制，只含字母、数字、- 和 _");
        }
        self.group = clip(self.group.trim(), 64);
        self.sound = clip(self.sound.trim(), 64);
        self.level = self.level.trim().to_owned();
        if !BARK_LEVELS.iter().any(|(v, _)| *v == self.level) {
            return Err("中断级别无效");
        }
        Ok(self)
    }
}

/// What a notification says, and the link opened when it is tapped.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Message {
    pub title: String,
    pub body: String,
    pub url: Option<String>,
    /// What a webhook is told besides the text.
    #[serde(skip)]
    pub context: Context,
}

/// Where a notification came from, for webhooks.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    /// `input`, `finished`, `failed`, `test` or `host`.
    pub event: String,
    pub computer: String,
    pub computer_name: String,
    pub session: String,
    pub session_title: String,
}

fn clip(text: &str, max: usize) -> String {
    text.chars()
        .filter(|c| !c.is_control() || *c == '\n')
        .take(max)
        .collect()
}

impl Message {
    fn tidy(&self) -> Self {
        Self {
            title: clip(&self.title, MAX_TITLE),
            body: clip(&self.body, MAX_BODY),
            // Only links into the app: a push must not open arbitrary pages.
            url: self
                .url
                .as_deref()
                .filter(|u| u.len() <= MAX_URL && u.starts_with(APP_LINK_PREFIX))
                .map(str::to_owned),
            context: self.context.clone(),
        }
    }
}

/// The URL scheme of the Runner Remote app (`runner-app/lib/core/links.dart`).
pub const APP_LINK_PREFIX: &str = "runner-remote://";

/// The app link that opens [session] on [computer] under [username]'s account on
/// this server, or just that account's computer list.
pub fn app_link(origin: &str, username: &str, target: Option<(i64, Option<&str>)>) -> String {
    let mut url = url::Url::parse(&format!("{APP_LINK_PREFIX}open")).expect("valid link");
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("server", origin);
        query.append_pair("user", username);
        if let Some((computer, session)) = target {
            query.append_pair("computer", &computer.to_string());
            if let Some(session) = session {
                query.append_pair("session", session);
            }
        }
    }
    url.into()
}

/// The icon pushed with every notification, served by this service.
pub fn icon_url(origin: &str) -> String {
    format!("{origin}/icon.png")
}

/// The HTTPS page on this service that forwards to [app_link], for places
/// that only open web links (chat apps, mail).
pub fn goto_url(app_link: &str) -> Option<String> {
    let url = url::Url::parse(app_link).ok()?;
    let server = url
        .query_pairs()
        .find(|(k, _)| k == "server")?
        .1
        .into_owned();
    Some(format!("{server}/go?{}", url.query().unwrap_or_default()))
}

/// The server a notification's app link names.
fn origin_of(app_link: &str) -> Option<String> {
    let url = url::Url::parse(app_link).ok()?;
    url.query_pairs()
        .find(|(k, _)| k == "server")
        .map(|(_, v)| v.into_owned())
}

/// What an event key is called in notifications.
pub fn event_name(event: &str) -> &'static str {
    match event {
        "input" => "需要输入",
        "finished" => "已完成",
        "failed" => "失败",
        "test" => "测试",
        _ => "通知",
    }
}

/// The values a webhook template may use, as `{{name}}`.
pub const TEMPLATE_VARIABLES: &[(&str, &str)] = &[
    ("title", "标题，Runner Remote"),
    ("message", "内容，例如 需要输入:修复登录"),
    ("body", "同 message"),
    ("event", "事件：input、finished、failed、test 或 host"),
    ("event_name", "事件名：需要输入、已完成、失败、测试"),
    ("session", "会话名"),
    ("session_id", "会话 ID"),
    ("computer", "电脑名"),
    ("computer_id", "电脑 ID"),
    ("group", "分组"),
    ("icon_url", "图标地址"),
    (
        "goto_url",
        "网页跳转链接：https 页面，打开后转到 App 中的会话",
    ),
    (
        "goto_url_schema",
        "直接跳转链接：runner-remote://…，直接打开 App 中的会话",
    ),
    ("url", "同 goto_url_schema"),
    ("date", "日期，例如 2026-11-22"),
    ("time", "时间，例如 14:05:09"),
    ("datetime", "日期和时间"),
    ("timestamp", "Unix 时间戳（秒）"),
];

/// The values of [TEMPLATE_VARIABLES] for [message], at [now].
pub fn variables(
    message: &Message,
    group: &str,
    now: chrono::DateTime<chrono::Local>,
) -> Vec<(&'static str, String)> {
    let c = &message.context;
    let app = message.url.clone().unwrap_or_default();
    let origin = origin_of(&app).unwrap_or_default();
    let group = if group.is_empty() { TITLE } else { group };
    vec![
        ("title", message.title.clone()),
        ("message", message.body.clone()),
        ("body", message.body.clone()),
        ("event", c.event.clone()),
        ("event_name", event_name(&c.event).into()),
        ("session", c.session_title.clone()),
        ("session_id", c.session.clone()),
        ("computer", c.computer_name.clone()),
        ("computer_id", c.computer.clone()),
        ("group", group.into()),
        (
            "icon_url",
            if origin.is_empty() {
                String::new()
            } else {
                icon_url(&origin)
            },
        ),
        ("goto_url", goto_url(&app).unwrap_or_default()),
        ("goto_url_schema", app.clone()),
        ("url", app),
        ("date", now.format("%Y-%m-%d").to_string()),
        ("time", now.format("%H:%M:%S").to_string()),
        ("datetime", now.format("%Y-%m-%d %H:%M:%S").to_string()),
        ("timestamp", now.timestamp().to_string()),
    ]
}

#[derive(Clone)]
pub struct Notifier {
    http: reqwest::Client,
}

impl Default for Notifier {
    fn default() -> Self {
        Self {
            http: reqwest::Client::builder()
                .timeout(TIMEOUT)
                .user_agent(concat!("runner-server/", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("HTTP client builds"),
        }
    }
}

#[derive(Serialize)]
struct BarkPush<'a> {
    device_key: &'a str,
    title: &'a str,
    body: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "str::is_empty")]
    group: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    sound: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    level: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    icon: Option<String>,
}

#[derive(Deserialize)]
struct BarkReply {
    #[serde(default)]
    code: i64,
    #[serde(default)]
    message: String,
}

impl Notifier {
    pub async fn send(&self, channel: &Channel, message: &Message) -> Result<()> {
        let message = message.tidy();
        match channel {
            Channel::Bark(bark) => self.bark(bark, &message).await,
            Channel::Ntfy(ntfy) => self.ntfy(ntfy, &message).await,
            Channel::Webhook(hook) => self.webhook(hook, &message).await,
        }
    }

    async fn ntfy(&self, ntfy: &Ntfy, message: &Message) -> Result<()> {
        let mut push = serde_json::json!({
            "topic": ntfy.topic,
            "title": message.title,
            "message": if message.body.is_empty() { &message.title } else { &message.body },
        });
        if ntfy.priority > 0 {
            push["priority"] = ntfy.priority.into();
        }
        let tags: Vec<&str> = ntfy
            .tags
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .collect();
        if !tags.is_empty() {
            push["tags"] = tags.into();
        }
        if let Some(url) = &message.url {
            push["click"] = url.as_str().into();
            if let Some(origin) = origin_of(url) {
                push["icon"] = icon_url(&origin).into();
            }
        }
        let mut request = self.http.post(&ntfy.server).json(&push);
        if !ntfy.token.is_empty() {
            request = request.bearer_auth(&ntfy.token);
        }
        let response = request.send().await.context("无法连接 ntfy 服务器")?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let detail: Option<serde_json::Value> = response.json().await.ok();
        match detail.as_ref().and_then(|d| d["error"].as_str()) {
            Some(error) => bail!("ntfy 返回错误 {status}：{error}"),
            None => bail!("ntfy 返回 HTTP {status}"),
        }
    }

    async fn webhook(&self, hook: &Webhook, message: &Message) -> Result<()> {
        let values = variables(message, &hook.group, chrono::Local::now());
        let body = if hook.template.trim().is_empty() {
            let mut json = serde_json::Map::new();
            for (name, value) in &values {
                json.insert(camel(name), value.clone().into());
            }
            serde_json::to_string(&json)?
        } else {
            let values: Vec<(&str, &str)> = values.iter().map(|(n, v)| (*n, v.as_str())).collect();
            render(&hook.template, &values)
        };
        let mut request = self.http.post(&hook.url).body(body);
        let mut typed = false;
        for (name, value) in &hook.headers {
            typed |= name.eq_ignore_ascii_case("content-type");
            request = request.header(name, value);
        }
        if !typed {
            request = request.header(reqwest::header::CONTENT_TYPE, "application/json");
        }
        let response = request.send().await.context("无法连接 Webhook 地址")?;
        let status = response.status();
        if !status.is_success() {
            bail!("Webhook 返回 HTTP {status}");
        }
        Ok(())
    }

    async fn bark(&self, bark: &Bark, message: &Message) -> Result<()> {
        let push = BarkPush {
            device_key: &bark.device_key,
            title: &message.title,
            body: if message.body.is_empty() {
                // Bark refuses an empty body.
                &message.title
            } else {
                &message.body
            },
            url: message.url.as_deref(),
            group: if bark.group.is_empty() {
                TITLE
            } else {
                &bark.group
            },
            sound: &bark.sound,
            level: &bark.level,
            icon: message
                .url
                .as_deref()
                .and_then(origin_of)
                .map(|o| icon_url(&o)),
        };
        let response = self
            .http
            .post(format!("{}/push", bark.server))
            .json(&push)
            .send()
            .await
            .context("无法连接 Bark 服务器")?;
        let status = response.status();
        let reply: Option<BarkReply> = response.json().await.ok();
        match reply {
            Some(r) if r.code == 200 => Ok(()),
            Some(r) => bail!("Bark 返回错误 {}：{}", r.code, r.message),
            None => Err(anyhow!("Bark 返回 HTTP {status}")),
        }
    }
}

/// The notification the "send a test" buttons push.
pub fn test_message(origin: &str, username: &str, phone: &str) -> Message {
    Message {
        title: TITLE.into(),
        body: format!("测试通知：{phone} 的通知设置正常。"),
        url: Some(app_link(origin, username, None)),
        context: Context {
            event: "test".into(),
            ..Context::default()
        },
    }
}

/// `event_name` → `eventName`, for the default webhook JSON.
fn camel(name: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in name.chars() {
        if c == '_' {
            upper = true;
        } else if upper {
            out.extend(c.to_uppercase());
            upper = false;
        } else {
            out.push(c);
        }
    }
    out
}

/// Fills `{{name}}` placeholders in a webhook template. Values are escaped as
/// the inside of a JSON string, so a JSON template stays valid.
pub fn render(template: &str, values: &[(&str, &str)]) -> String {
    let mut out = template.to_owned();
    for (name, value) in values {
        let quoted = serde_json::to_string(value).unwrap_or_default();
        let escaped = &quoted[1..quoted.len() - 1];
        out = out.replace(&format!("{{{{{name}}}}}"), escaped);
    }
    out
}

/// Delivers [message] to [device], a phone of [user_id], if it has a channel
/// and, for a session [event], wants that kind. Returns whether it was sent.
pub async fn deliver(
    state: &AppState,
    user_id: i64,
    device: i64,
    event: Option<Event>,
    message: Message,
) -> Result<bool> {
    let found = state
        .db
        .call(move |c| {
            let Some(host) = db::host_by_id(c, device)? else {
                return Ok(None);
            };
            if host.user_id != user_id || host.kind != DeviceKind::Phone {
                return Ok(None);
            }
            db::notify_settings(c, device).map(Some)
        })
        .await?;
    let Some((Some(channel), events)) = found else {
        return Ok(false);
    };
    if event.is_some_and(|e| !e.wanted(&events)) {
        return Ok(false);
    }
    state.notifier.send(&channel, &message).await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templates_escape_values_as_json() {
        let out = render(
            r#"{"text":"{{title}}: {{body}}","x":"{{missing}}"}"#,
            &[
                ("title", "Runner Remote"),
                ("body", "[已完成]:say \"hi\"\n"),
            ],
        );
        assert_eq!(
            out,
            r#"{"text":"Runner Remote: [已完成]:say \"hi\"\n","x":"{{missing}}"}"#
        );
        serde_json::from_str::<serde_json::Value>(&out).unwrap();
    }

    #[test]
    fn webhooks_get_every_variable() {
        use chrono::TimeZone;
        let message = Message {
            title: TITLE.into(),
            body: "需要输入:Fix login".into(),
            url: Some(app_link(
                "https://r.example.com",
                "alice",
                Some((42, Some("s1"))),
            )),
            context: Context {
                event: "input".into(),
                computer: "42".into(),
                computer_name: "studio".into(),
                session: "s1".into(),
                session_title: "Fix login".into(),
            },
        };
        let now = chrono::Local
            .with_ymd_and_hms(2026, 11, 22, 14, 5, 9)
            .unwrap();
        let values: std::collections::HashMap<_, _> =
            variables(&message, "", now).into_iter().collect();
        assert_eq!(
            values
                .keys()
                .copied()
                .collect::<std::collections::BTreeSet<_>>(),
            TEMPLATE_VARIABLES.iter().map(|(n, _)| *n).collect()
        );
        assert_eq!(values["message"], "需要输入:Fix login");
        assert_eq!(values["event_name"], "需要输入");
        assert_eq!(values["group"], "Runner Remote");
        assert_eq!(values["icon_url"], "https://r.example.com/icon.png");
        assert_eq!(
            values["goto_url"],
            "https://r.example.com/go?server=https%3A%2F%2Fr.example.com&user=alice&computer=42&session=s1"
        );
        assert!(values["goto_url_schema"].starts_with("runner-remote://open?"));
        assert_eq!(
            (values["date"].as_str(), values["time"].as_str()),
            ("2026-11-22", "14:05:09")
        );
        assert_eq!(camel("icon_url"), "iconUrl");
    }

    #[test]
    fn channels_validate_and_keep_their_shape() {
        let ntfy: Channel =
            serde_json::from_str(r#"{"kind":"ntfy","topic":" runner_1 ","priority":4}"#).unwrap();
        let Channel::Ntfy(n) = ntfy.validate().unwrap() else {
            panic!()
        };
        assert_eq!(
            (n.server.as_str(), n.topic.as_str()),
            (DEFAULT_NTFY_SERVER, "runner_1")
        );
        let bad: Channel = serde_json::from_str(r#"{"kind":"ntfy","topic":"a/b"}"#).unwrap();
        assert!(bad.validate().is_err());
        let hook: Channel = serde_json::from_str(
            r#"{"kind":"webhook","url":"https://example.com/h","headers":{" X-Key ":" v "}}"#,
        )
        .unwrap();
        let Channel::Webhook(w) = hook.validate().unwrap() else {
            panic!()
        };
        assert_eq!(w.headers.get("X-Key").map(String::as_str), Some("v"));
        let bad: Channel =
            serde_json::from_str(r#"{"kind":"webhook","url":"ftp://example.com"}"#).unwrap();
        assert!(bad.validate().is_err());
    }
}
