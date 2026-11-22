//! The parts of Runner's remote access protocol the service speaks, copied from
//! `runner-core` (`remote/` and `companion/channel/`) at Runner `12c867d2`.
//! Keep them byte-compatible with Runner; `tests/fixtures/` are Runner's own
//! golden messages. Runner is MIT-licensed; see `licenses/runner-LICENSE`.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use url::Url;

pub const SUBPROTOCOL: &str = "runner-relay.v1";
pub const CLIENT_SUBPROTOCOL: &str = "runner-client.v1";
pub const MAX_CONTROL_SIZE: usize = 64 * 1024;
/// Largest channel frame: Noise's 65,535-byte message plus the frame's kind byte.
pub const MAX_FRAME: usize = 65_536;
/// A host-side relay frame: a channel frame behind its 4-byte channel number.
pub const MAX_RELAY_SIZE: usize = MAX_FRAME + 4;

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct HostInfo {
    pub hostname: String,
    pub platform: String,
    pub arch: String,
    pub os_version: String,
    pub runner_version: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct Account {
    pub username: String,
    pub display_name: String,
}

/// What kind of device is enrolling. Runner never sends it, so its enrollments
/// are computers. A phone only opens client routes, so it is never listed as a
/// computer to connect to.
///
/// On the wire this is the official service's `EnrollmentKind`
/// (`ENROLLMENT_KIND_HOST` / `ENROLLMENT_KIND_CLIENT`, or their numbers 1 / 2).
/// It serializes as `"phone"` / `"computer"`, which is what
/// `channelOpen.device.kind` carries.
#[derive(Clone, Copy, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Phone,
    /// Also any value this server does not know.
    #[default]
    Computer,
}

impl<'de> Deserialize<'de> for DeviceKind {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(match serde_json::Value::deserialize(d)? {
            serde_json::Value::String(s) if s == "ENROLLMENT_KIND_CLIENT" => Self::Phone,
            serde_json::Value::Number(n) if n.as_u64() == Some(2) => Self::Phone,
            _ => Self::Computer,
        })
    }
}

impl DeviceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Computer => "computer",
            Self::Phone => "phone",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "phone" => Self::Phone,
            _ => Self::Computer,
        }
    }

    pub fn is_computer(&self) -> bool {
        *self == Self::Computer
    }
}

/// What a phone says about itself (the official service's `ClientInfo`).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, rename_all = "camelCase")]
pub struct ClientInfo {
    pub name: String,
    pub platform: String,
    pub os_version: String,
    pub runner_version: String,
}

impl ClientInfo {
    /// Phones are stored with the computers; their info goes in a [HostInfo].
    pub fn into_host_info(self) -> HostInfo {
        HostInfo {
            hostname: self.name,
            platform: self.platform,
            arch: String::new(),
            os_version: self.os_version,
            runner_version: self.runner_version,
        }
    }

    pub fn from_host_info(info: &HostInfo) -> Self {
        Self {
            name: info.hostname.clone(),
            platform: info.platform.clone(),
            os_version: info.os_version.clone(),
            runner_version: info.runner_version.clone(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct StartRequest {
    pub host: HostInfo,
    pub host_key: String,
    #[serde(skip_serializing_if = "DeviceKind::is_computer")]
    pub kind: DeviceKind,
    /// A phone's details, sent with `ENROLLMENT_KIND_CLIENT` instead of
    /// [StartRequest::host] and [StartRequest::host_key].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<ClientInfo>,
}

impl StartRequest {
    /// The device's info: a phone's [ClientInfo], a computer's `host`.
    pub fn device_info(self) -> HostInfo {
        match self.kind {
            DeviceKind::Phone => self.client.unwrap_or_default().into_host_info(),
            DeviceKind::Computer => self.host,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct StartResponse {
    pub device_code: Secret,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: String,
    pub expires_in: i32,
    pub interval: i32,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PollRequest {
    pub device_code: Secret,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PollResponse {
    pub state: EnrollmentState,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub host_id: String,
    #[serde(skip_serializing_if = "secret_empty")]
    pub credential: Secret,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub relay_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account: Option<Account>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claim_expires_at: Option<String>,
    /// A phone's id, which the official service sends instead of `hostId`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub client_id: String,
    /// This service's version, sent to a phone with its credential; the
    /// official service sends none, which is how the app tells them apart.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub server_version: String,
}
fn secret_empty(s: &Secret) -> bool {
    s.0.is_empty()
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnrollmentState {
    #[serde(rename = "ENROLLMENT_STATE_PENDING")]
    Pending,
    #[serde(rename = "ENROLLMENT_STATE_DENIED")]
    Denied,
    #[serde(rename = "ENROLLMENT_STATE_EXPIRED")]
    Expired,
    #[serde(rename = "ENROLLMENT_STATE_APPROVED")]
    Approved,
    #[default]
    #[serde(other, rename = "ENROLLMENT_STATE_UNSPECIFIED")]
    Unspecified,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Empty {}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Control {
    Hello {
        #[serde(default)]
        host: HostInfo,
        #[serde(default)]
        features: Vec<String>,
    },
    Welcome {
        #[serde(default, rename = "hostId")]
        host_id: String,
        #[serde(default)]
        name: String,
        #[serde(default)]
        account: Account,
    },
    /// `device` is this service's addition: the device that opened the channel.
    /// Runner ignores it; a host that knows it uses it to address [Control::Notify].
    #[serde(rename = "channelOpen")]
    ChannelOpen {
        channel: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device: Option<ChannelDevice>,
    },
    #[serde(rename = "channelClosed")]
    ChannelClosed { channel: u32 },
    #[serde(rename = "closeChannel")]
    CloseChannel { channel: u32 },
    /// Host to service: notify [device], a phone of the same account, about
    /// [session]. The service delivers it through the phone's channel and adds
    /// the link that opens the session in the app. Not part of Runner's protocol.
    Notify {
        device: String,
        #[serde(default)]
        session: Option<String>,
        #[serde(default)]
        title: String,
        #[serde(default)]
        body: String,
    },
    #[serde(other)]
    Unknown,
}

/// The device behind a channel, as `channelOpen` names it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ChannelDevice {
    pub id: String,
    pub kind: DeviceKind,
}

/// One computer in `HostClientService/ListAccountHosts`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Computer {
    pub id: String,
    pub name: String,
    pub info: HostInfo,
    pub fingerprint: String,
    pub online: bool,
    pub connected_at: Option<String>,
    pub last_seen_at: Option<String>,
    #[serde(rename = "self")]
    pub is_self: bool,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Computers {
    pub hosts: Vec<Computer>,
}

/// The host key fingerprint Runner shows and pins: the first ten bytes of the
/// key's SHA-256, as five space-separated groups of four hex digits.
pub fn fingerprint(public: &[u8]) -> String {
    Sha256::digest(public)[..10]
        .chunks(2)
        .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn decode_key(encoded: &str) -> Option<Vec<u8>> {
    STANDARD.decode(encoded).ok().filter(|k| k.len() == 32)
}

/// The device a bearer credential belongs to: a computer's `rhc_` or a phone's
/// `rcc_`, as the official service issues them. None for anything else.
pub fn credential_kind(value: &str) -> Option<DeviceKind> {
    if valid_credential(value) {
        return Some(DeviceKind::Computer);
    }
    value
        .strip_prefix("rcc_")
        .is_some_and(|token| valid_credential(&format!("rhc_{token}")))
        .then_some(DeviceKind::Phone)
}

/// Runner rejects an enrollment credential that is not `rhc_` and 43 URL-safe characters.
pub fn valid_credential(value: &str) -> bool {
    value.strip_prefix("rhc_").is_some_and(|token| {
        token.len() == 43
            && token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    })
}

pub fn canonical_origin(value: &str) -> Result<String, &'static str> {
    let url = Url::parse(value).map_err(|_| "Enter a valid service origin.")?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err("Service origin must have no path, user info, query or fragment.");
    }
    if url.scheme() != "https"
        && !(url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1")))
    {
        return Err("Service origin must use HTTPS; explicit HTTP localhost is allowed.");
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// The check Runner applies to `relayUrl` in an approved poll.
pub fn valid_relay_url(origin: &str, relay: &str) -> bool {
    let (Ok(origin), Ok(relay)) = (Url::parse(origin), Url::parse(relay)) else {
        return false;
    };
    relay.scheme()
        == if origin.scheme() == "https" {
            "wss"
        } else {
            "ws"
        }
        && relay.host_str() == origin.host_str()
        && relay.port_or_known_default() == origin.port_or_known_default()
        && relay.username().is_empty()
        && relay.password().is_none()
        && relay.path() == "/relay/host"
        && relay.query().is_none()
        && relay.fragment().is_none()
}

/// Prefix a channel frame with its channel number for `/relay/host`.
pub fn wrap(channel: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = channel.to_be_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

/// Split a `/relay/host` frame into its channel number and channel frame.
pub fn unwrap(bytes: &[u8]) -> Option<(u32, &[u8])> {
    if !(4..=MAX_FRAME + 4).contains(&bytes.len()) {
        return None;
    }
    let channel = u32::from_be_bytes(bytes[..4].try_into().ok()?);
    (channel != 0).then_some((channel, &bytes[4..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::DeserializeOwned;

    fn round_trip<T: DeserializeOwned + Serialize>(name: &str) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name);
        let data = std::fs::read(path).unwrap();
        let value: T = serde_json::from_slice(&data).unwrap();
        assert_eq!(
            serde_json::to_value(value).unwrap(),
            serde_json::from_slice::<serde_json::Value>(&data).unwrap(),
            "{name}"
        );
    }

    #[test]
    fn runner_golden_fixtures() {
        round_trip::<StartRequest>("start_request.json");
        round_trip::<StartResponse>("start_response.json");
        round_trip::<PollRequest>("poll_request.json");
        for name in [
            "poll_approved.json",
            "poll_pending.json",
            "poll_denied.json",
            "poll_expired.json",
        ] {
            round_trip::<PollResponse>(name);
        }
        round_trip::<RpcError>("rpc_error.json");
        round_trip::<Empty>("signout.json");
        round_trip::<Control>("hello.json");
        round_trip::<Control>("welcome.json");
        for name in [
            "channel_open.json",
            "channel_closed.json",
            "close_channel.json",
        ] {
            round_trip::<Control>(name);
        }
        round_trip::<Computers>("list_account_hosts.json");
    }

    #[test]
    fn channel_open_names_the_device_and_notify_parses() {
        let open = Control::ChannelOpen {
            channel: 3,
            device: Some(ChannelDevice {
                id: "42".into(),
                kind: DeviceKind::Phone,
            }),
        };
        assert_eq!(
            serde_json::to_value(&open).unwrap(),
            serde_json::json!({"type":"channelOpen","channel":3,"device":{"id":"42","kind":"phone"}})
        );
        let notify: Control = serde_json::from_str(
            r#"{"type":"notify","device":"42","session":"s1","title":"t","body":"b"}"#,
        )
        .unwrap();
        assert!(
            matches!(notify, Control::Notify { device, session: Some(s), .. } if device == "42" && s == "s1")
        );
    }

    #[test]
    fn device_kind_defaults_to_computer() {
        let runner: StartRequest = serde_json::from_str(r#"{"hostKey":"k"}"#).unwrap();
        assert_eq!(runner.kind, DeviceKind::Computer);
        let phone: StartRequest = serde_json::from_str(r#"{"kind":"phone"}"#).unwrap();
        assert_eq!(phone.kind, DeviceKind::Computer, "only the official kinds");
        let unknown: StartRequest = serde_json::from_str(r#"{"kind":"toaster"}"#).unwrap();
        assert_eq!(unknown.kind, DeviceKind::Computer);
        for (json, kind) in [
            (r#"{"kind":"ENROLLMENT_KIND_CLIENT"}"#, DeviceKind::Phone),
            (r#"{"kind":2}"#, DeviceKind::Phone),
            (r#"{"kind":"ENROLLMENT_KIND_HOST"}"#, DeviceKind::Computer),
            (r#"{"kind":1}"#, DeviceKind::Computer),
        ] {
            assert_eq!(
                serde_json::from_str::<StartRequest>(json).unwrap().kind,
                kind,
                "{json}"
            );
        }
        let official: StartRequest = serde_json::from_str(
            r#"{"kind":"ENROLLMENT_KIND_CLIENT","client":{"name":"iPhone","platform":"ios","osVersion":"18.1","runnerVersion":"1.0"},"host":{"hostname":"ignored"}}"#,
        )
        .unwrap();
        let info = official.device_info();
        assert_eq!(info.hostname, "iPhone");
        assert_eq!(info.os_version, "18.1");
        assert_eq!(
            DeviceKind::parse(DeviceKind::Phone.as_str()),
            DeviceKind::Phone
        );
    }

    #[test]
    fn origins_relay_urls_and_credentials() {
        assert_eq!(
            canonical_origin("https://Runner.Example:443/").unwrap(),
            "https://runner.example"
        );
        for bad in [
            "http://example.com",
            "ftp://localhost",
            "https://u:p@example.com",
            "https://example.com/path",
            "https://example.com?q=1",
        ] {
            assert!(canonical_origin(bad).is_err(), "{bad}");
        }
        assert!(canonical_origin("http://localhost:8000").is_ok());
        assert!(valid_relay_url(
            "https://example.com",
            "wss://example.com/relay/host"
        ));
        assert!(!valid_relay_url(
            "https://example.com",
            "ws://example.com/relay/host"
        ));
        assert!(valid_credential(
            "rhc_Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx"
        ));
        assert!(!valid_credential("rhc_short"));
        let token = "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx";
        assert_eq!(
            credential_kind(&format!("rhc_{token}")),
            Some(DeviceKind::Computer)
        );
        assert_eq!(
            credential_kind(&format!("rcc_{token}")),
            Some(DeviceKind::Phone)
        );
        assert_eq!(credential_kind("rcc_short"), None);
        assert_eq!(credential_kind(&format!("rxx_{token}")), None);
    }

    #[test]
    fn fingerprints_and_channel_frames() {
        assert_eq!(fingerprint(&[0; 32]), "6668 7aad f862 bd77 6c8f");
        assert_eq!(wrap(17, &[1, 2]), vec![0, 0, 0, 17, 1, 2]);
        assert_eq!(unwrap(&[0, 0, 0, 17, 1, 2]), Some((17, &[1, 2][..])));
        assert_eq!(unwrap(&[0, 0, 0, 0, 1]), None);
        assert_eq!(unwrap(&[0, 0, 1]), None);
    }
}
