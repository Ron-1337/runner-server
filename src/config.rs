use anyhow::anyhow;

#[derive(Clone, Debug)]
pub struct Config {
    pub origin: String,
    pub secure_cookies: bool,
}

impl Config {
    pub fn new(origin: &str) -> anyhow::Result<Self> {
        let origin = crate::protocol::canonical_origin(origin).map_err(|e| anyhow!(e))?;
        Ok(Self {
            secure_cookies: origin.starts_with("https://"),
            origin,
        })
    }

    pub fn relay_url(&self) -> String {
        format!("{}/relay/host", self.origin.replacen("http", "ws", 1))
    }

    /// Where phones connect, as the official service tells its clients.
    pub fn client_relay_url(&self) -> String {
        format!("{}/relay/client", self.origin.replacen("http", "ws", 1))
    }
}
