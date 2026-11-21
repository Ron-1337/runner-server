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

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct StartRequest {
    pub host: HostInfo,
    pub host_key: String,
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
    #[serde(rename = "channelOpen")]
    ChannelOpen { channel: u32 },
    #[serde(rename = "channelClosed")]
    ChannelClosed { channel: u32 },
    #[serde(rename = "closeChannel")]
    CloseChannel { channel: u32 },
    #[serde(other)]
    Unknown,
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
