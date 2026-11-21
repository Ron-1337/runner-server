//! Notifications to phones through third-party push services.
//!
//! A phone has no connection to this service while the app is in the
//! background, so a computer asks the service to push for it: the computer
//! sends a `notify` control message on `/relay/host` naming the phone, and the
//! service delivers it through the channel configured for that phone on the
//! web page. Only Bark (iOS) is supported for now.

use crate::{AppState, db, protocol::DeviceKind};
use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_BARK_SERVER: &str = "https://api.day.app";
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
        }
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
            group: &bark.group,
            sound: &bark.sound,
            level: &bark.level,
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

/// Delivers [message] to [device], a phone of [user_id], if it has a channel.
/// Returns whether a channel was configured.
pub async fn deliver(
    state: &AppState,
    user_id: i64,
    device: i64,
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
            db::notify_channel(c, device)
        })
        .await?;
    let Some(channel) = found else {
        return Ok(false);
    };
    state.notifier.send(&channel, &message).await?;
    Ok(true)
}
