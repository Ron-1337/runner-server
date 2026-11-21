use crate::{AppState, db, db::User, now, web::WebError};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng as HashRng},
};
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, header, request::Parts},
    response::{IntoResponse, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{Rng, RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::{LazyLock, Mutex},
    time::{Duration, Instant},
};

pub const SESSION_COOKIE: &str = "rs_session";
pub const SESSION_TTL: i64 = 30 * 24 * 3600;
const USER_CODE_ALPHABET: &[u8] = b"BCDFGHJKLMNPQRSTVWXZ";

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut HashRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("password hashing failed: {e}"))
}

static DUMMY_HASH: LazyLock<String> =
    LazyLock::new(|| hash_password("runner-server-dummy").expect("hash dummy password"));

pub fn verify_password(password: &str, hash: Option<&str>) -> bool {
    let hash = hash.unwrap_or(DUMMY_HASH.as_str());
    let ok = PasswordHash::new(hash).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    });
    ok && hash != DUMMY_HASH.as_str()
}

pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn credential() -> String {
    format!("rhc_{}", random_token())
}

pub fn sha256_hex(value: &str) -> String {
    Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn user_code() -> String {
    let mut code = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            code.push('-');
        }
        code.push(USER_CODE_ALPHABET[OsRng.gen_range(0..USER_CODE_ALPHABET.len())] as char);
    }
    code
}

pub fn normalize_user_code(input: &str) -> Option<String> {
    let letters: String = input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    (letters.len() == 8 && letters.bytes().all(|b| USER_CODE_ALPHABET.contains(&b)))
        .then(|| format!("{}-{}", &letters[..4], &letters[4..]))
}

pub fn host_id() -> i64 {
    OsRng.gen_range(1..(1i64 << 53))
}

pub fn validate_username(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 32 {
        return Err("用户名长度需为 1–32 个字符。");
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err("用户名只能包含字母、数字、下划线、连字符和点。");
    }
    Ok(())
}

pub fn validate_password(password: &str, confirm: &str) -> Result<(), &'static str> {
    if password.chars().count() < 8 {
        return Err("密码至少 8 个字符。");
    }
    if password.len() > 256 {
        return Err("密码过长。");
    }
    if password != confirm {
        return Err("两次输入的密码不一致。");
    }
    Ok(())
}

#[derive(Default)]
pub struct LoginLimiter(Mutex<HashMap<String, (u32, Instant)>>);

impl LoginLimiter {
    const MAX_FAILURES: u32 = 10;
    const WINDOW: Duration = Duration::from_secs(15 * 60);

    pub fn allowed(&self, key: &str) -> bool {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, (_, at)| at.elapsed() < Self::WINDOW);
        map.get(key).is_none_or(|(n, _)| *n < Self::MAX_FAILURES)
    }

    pub fn fail(&self, key: &str) {
        let mut map = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(key.to_owned()).or_insert((0, Instant::now()));
        entry.0 += 1;
        entry.1 = Instant::now();
    }

    pub fn clear(&self, key: &str) {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(key);
    }
}

pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
}

pub fn session_cookie(token: &str, secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_TTL}{}",
        if secure { "; Secure" } else { "" }
    )
}

pub fn clear_cookie(secure: bool) -> String {
    format!(
        "{SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        if secure { "; Secure" } else { "" }
    )
}

pub fn bearer(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    runner_core::remote::valid_credential(token).then(|| token.to_owned())
}

pub async fn start_session(state: &AppState, user_id: i64) -> anyhow::Result<String> {
    let token = random_token();
    let hash = sha256_hex(&token);
    let expires = now() + SESSION_TTL;
    state
        .db
        .call(move |c| db::insert_session(c, &hash, user_id, expires))
        .await?;
    Ok(token)
}

pub struct CurrentUser {
    pub user: User,
    pub session: String,
}

pub async fn current_user(
    state: &AppState,
    headers: &HeaderMap,
) -> anyhow::Result<Option<CurrentUser>> {
    let Some(token) = cookie_value(headers, SESSION_COOKIE) else {
        return Ok(None);
    };
    let session = sha256_hex(&token);
    let lookup = session.clone();
    let now = now();
    let user = state
        .db
        .call(move |c| db::session_user(c, &lookup, now))
        .await?;
    Ok(user.map(|user| CurrentUser { user, session }))
}

pub fn login_redirect(next: &str) -> Response {
    let next: String = url::form_urlencoded::byte_serialize(next.as_bytes()).collect();
    Redirect::to(&format!("/login?next={next}")).into_response()
}

impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        match current_user(state, &parts.headers).await {
            Ok(Some(user)) => Ok(user),
            Ok(None) => {
                let next = if parts.method == axum::http::Method::GET {
                    parts.uri.path_and_query().map_or("/", |p| p.as_str())
                } else {
                    "/"
                };
                Err(login_redirect(next))
            }
            Err(e) => Err(WebError::from(e).into_response()),
        }
    }
}

pub struct AdminUser(pub CurrentUser);

impl FromRequestParts<AppState> for AdminUser {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> Result<Self, Response> {
        let current = CurrentUser::from_request_parts(parts, state).await?;
        if !current.user.is_admin {
            return Err(crate::html::forbidden(&current.user));
        }
        Ok(Self(current))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_and_credentials_match_runner_formats() {
        assert!(runner_core::remote::valid_credential(&credential()));
        let code = user_code();
        assert_eq!(
            normalize_user_code(&code.to_lowercase().replace('-', " ")),
            Some(code)
        );
        assert_eq!(normalize_user_code("AAAA-AAAA"), None);
        assert!((1..(1i64 << 53)).contains(&host_id()));
    }

    #[test]
    fn passwords_verify() {
        let hash = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", Some(&hash)));
        assert!(!verify_password("wrong", Some(&hash)));
        assert!(!verify_password("runner-server-dummy", None));
    }
}
