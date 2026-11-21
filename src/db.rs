use crate::{
    notify::Channel,
    protocol::{DeviceKind, HostInfo},
};
use anyhow::Result;
use rusqlite::{Connection, ErrorCode, OptionalExtension, Row, params};
use std::{
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS web_sessions_user ON web_sessions(user_id);
CREATE TABLE IF NOT EXISTS enrollments (
    device_hash TEXT PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    host_key TEXT NOT NULL,
    info TEXT NOT NULL,
    state TEXT NOT NULL,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    info TEXT NOT NULL,
    host_key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    credential_hash TEXT NOT NULL UNIQUE,
    activated INTEGER NOT NULL DEFAULT 0,
    claim_expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER
);
CREATE INDEX IF NOT EXISTS hosts_user ON hosts(user_id);
CREATE INDEX IF NOT EXISTS hosts_key ON hosts(host_key);
CREATE TABLE IF NOT EXISTS notify_channels (
    host_id INTEGER PRIMARY KEY REFERENCES hosts(id) ON DELETE CASCADE,
    config TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);
"#;

/// Columns added after the first release, as (table, column, definition).
const ADDED_COLUMNS: &[(&str, &str, &str)] = &[
    ("enrollments", "kind", "TEXT NOT NULL DEFAULT 'computer'"),
    ("hosts", "kind", "TEXT NOT NULL DEFAULT 'computer'"),
    ("users", "last_login_at", "INTEGER"),
    ("enrollments", "requesting_ip", "TEXT NOT NULL DEFAULT ''"),
    ("enrollments", "name", "TEXT NOT NULL DEFAULT ''"),
];

fn migrate(c: &Connection) -> Result<()> {
    for (table, column, definition) in ADDED_COLUMNS {
        let present: bool = c.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info(?1) WHERE name = ?2",
            params![table, column],
            |r| r.get(0),
        )?;
        if !present {
            c.execute_batch(&format!(
                "ALTER TABLE {table} ADD COLUMN {column} {definition}"
            ))?;
        }
    }
    Ok(())
}

#[derive(Clone)]
pub struct Db(Arc<Mutex<Connection>>);

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.query_row("PRAGMA journal_mode=WAL", [], |_| Ok(()))?;
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")?;
        conn.execute_batch(SCHEMA)?;
        migrate(&conn)?;
        Ok(Self(Arc::new(Mutex::new(conn))))
    }

    pub fn lock(&self) -> MutexGuard<'_, Connection> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub async fn call<T, F>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&mut Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let db = self.clone();
        tokio::task::spawn_blocking(move || f(&mut db.lock())).await?
    }
}

fn duplicate(e: &rusqlite::Error) -> bool {
    matches!(e, rusqlite::Error::SqliteFailure(f, _) if f.code == ErrorCode::ConstraintViolation)
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
    pub is_admin: bool,
    pub disabled: bool,
    pub created_at: i64,
    pub last_login_at: Option<i64>,
}

const USER_COLS: &str =
    "u.id, u.username, u.display_name, u.is_admin, u.disabled, u.created_at, u.last_login_at";
/// Number of columns in `USER_COLS`.
const USER_WIDTH: usize = 7;

fn user_at(r: &Row, at: usize) -> rusqlite::Result<User> {
    Ok(User {
        id: r.get(at)?,
        username: r.get(at + 1)?,
        display_name: r.get(at + 2)?,
        is_admin: r.get(at + 3)?,
        disabled: r.get(at + 4)?,
        created_at: r.get(at + 5)?,
        last_login_at: r.get(at + 6)?,
    })
}

pub fn user_count(c: &Connection) -> Result<i64> {
    Ok(c.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))?)
}

pub fn insert_user(
    c: &Connection,
    username: &str,
    display_name: &str,
    password_hash: &str,
    is_admin: bool,
    now: i64,
) -> Result<Option<i64>> {
    match c.execute(
        "INSERT INTO users (username, display_name, password_hash, is_admin, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![username, display_name, password_hash, is_admin, now],
    ) {
        Ok(_) => Ok(Some(c.last_insert_rowid())),
        Err(e) if duplicate(&e) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn user_by_id(c: &Connection, id: i64) -> Result<Option<User>> {
    Ok(c.query_row(
        &format!("SELECT {USER_COLS} FROM users u WHERE u.id = ?1"),
        [id],
        |r| user_at(r, 0),
    )
    .optional()?)
}

pub fn user_with_hash(c: &Connection, username: &str) -> Result<Option<(User, String)>> {
    Ok(c.query_row(
        &format!("SELECT {USER_COLS}, u.password_hash FROM users u WHERE u.username = ?1"),
        [username],
        |r| Ok((user_at(r, 0)?, r.get(USER_WIDTH)?)),
    )
    .optional()?)
}

pub fn password_hash(c: &Connection, id: i64) -> Result<Option<String>> {
    Ok(
        c.query_row("SELECT password_hash FROM users WHERE id = ?1", [id], |r| {
            r.get(0)
        })
        .optional()?,
    )
}

pub fn list_users(c: &Connection) -> Result<Vec<User>> {
    let mut stmt = c.prepare(&format!("SELECT {USER_COLS} FROM users u ORDER BY u.id"))?;
    let rows = stmt.query_map([], |r| user_at(r, 0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn set_password(c: &Connection, id: i64, hash: &str) -> Result<bool> {
    Ok(c.execute(
        "UPDATE users SET password_hash = ?2 WHERE id = ?1",
        params![id, hash],
    )? > 0)
}

pub fn set_admin(c: &Connection, id: i64, admin: bool) -> Result<bool> {
    Ok(c.execute(
        "UPDATE users SET is_admin = ?2 WHERE id = ?1",
        params![id, admin],
    )? > 0)
}

pub fn set_disabled(c: &Connection, id: i64, disabled: bool) -> Result<bool> {
    Ok(c.execute(
        "UPDATE users SET disabled = ?2 WHERE id = ?1",
        params![id, disabled],
    )? > 0)
}

pub fn touch_login(c: &Connection, id: i64, now: i64) -> Result<()> {
    c.execute(
        "UPDATE users SET last_login_at = ?2 WHERE id = ?1",
        params![id, now],
    )?;
    Ok(())
}

pub fn delete_user(c: &Connection, id: i64) -> Result<bool> {
    Ok(c.execute("DELETE FROM users WHERE id = ?1", [id])? > 0)
}

pub fn insert_session(
    c: &Connection,
    token_hash: &str,
    user_id: i64,
    expires_at: i64,
) -> Result<()> {
    c.execute(
        "INSERT INTO web_sessions (token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
        params![token_hash, user_id, expires_at],
    )?;
    Ok(())
}

pub fn session_user(c: &Connection, token_hash: &str, now: i64) -> Result<Option<User>> {
    Ok(c.query_row(
        &format!(
            "SELECT {USER_COLS} FROM web_sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = ?1 AND s.expires_at > ?2 AND u.disabled = 0"
        ),
        params![token_hash, now],
        |r| user_at(r, 0),
    )
    .optional()?)
}

/// Moves a live session's expiry to [expires_at]; false when it is gone or expired.
pub fn extend_session(c: &Connection, token_hash: &str, expires_at: i64, now: i64) -> Result<bool> {
    Ok(c.execute(
        "UPDATE web_sessions SET expires_at = ?2 WHERE token_hash = ?1 AND expires_at > ?3",
        params![token_hash, expires_at, now],
    )? > 0)
}

pub fn delete_session(c: &Connection, token_hash: &str) -> Result<()> {
    c.execute(
        "DELETE FROM web_sessions WHERE token_hash = ?1",
        [token_hash],
    )?;
    Ok(())
}

pub fn delete_sessions(c: &Connection, user_id: i64, keep: Option<&str>) -> Result<()> {
    c.execute(
        "DELETE FROM web_sessions WHERE user_id = ?1 AND token_hash IS NOT ?2",
        params![user_id, keep],
    )?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Enrollment {
    pub device_hash: String,
    pub user_code: String,
    pub host_key: String,
    pub info: HostInfo,
    pub state: String,
    pub user_id: Option<i64>,
    pub expires_at: i64,
    pub kind: DeviceKind,
    /// The address StartEnrollment came from, shown on the approval page.
    pub requesting_ip: String,
    /// The name chosen when approving; empty for the device's own name.
    pub name: String,
    /// Set by the database; ignored by [insert_enrollment].
    pub created_at: i64,
}

const ENROLLMENT_COLS: &str = "device_hash, user_code, host_key, info, state, user_id, expires_at, kind, requesting_ip, name, created_at";

fn enrollment_row(r: &Row) -> rusqlite::Result<Enrollment> {
    Ok(Enrollment {
        device_hash: r.get(0)?,
        user_code: r.get(1)?,
        host_key: r.get(2)?,
        info: serde_json::from_str(&r.get::<_, String>(3)?).unwrap_or_default(),
        state: r.get(4)?,
        user_id: r.get(5)?,
        expires_at: r.get(6)?,
        kind: DeviceKind::parse(&r.get::<_, String>(7)?),
        requesting_ip: r.get(8)?,
        name: r.get(9)?,
        created_at: r.get(10)?,
    })
}

pub fn insert_enrollment(c: &Connection, e: &Enrollment, now: i64) -> Result<bool> {
    match c.execute(
        "INSERT INTO enrollments (device_hash, user_code, host_key, info, state, user_id, created_at, expires_at, kind, requesting_ip)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            e.device_hash,
            e.user_code,
            e.host_key,
            serde_json::to_string(&e.info)?,
            e.state,
            e.user_id,
            now,
            e.expires_at,
            e.kind.as_str(),
            e.requesting_ip
        ],
    ) {
        Ok(_) => Ok(true),
        Err(e) if duplicate(&e) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

pub fn pending_enrollments(c: &Connection, now: i64) -> Result<i64> {
    Ok(c.query_row(
        "SELECT COUNT(*) FROM enrollments WHERE expires_at > ?1",
        [now],
        |r| r.get(0),
    )?)
}

pub fn enrollment_by_code(c: &Connection, user_code: &str) -> Result<Option<Enrollment>> {
    Ok(c.query_row(
        &format!("SELECT {ENROLLMENT_COLS} FROM enrollments WHERE user_code = ?1"),
        [user_code],
        enrollment_row,
    )
    .optional()?)
}

pub fn enrollment_by_device(c: &Connection, device_hash: &str) -> Result<Option<Enrollment>> {
    Ok(c.query_row(
        &format!("SELECT {ENROLLMENT_COLS} FROM enrollments WHERE device_hash = ?1"),
        [device_hash],
        enrollment_row,
    )
    .optional()?)
}

/// Approves or denies a pending enrollment; [name] renames the device on approval.
pub fn decide_enrollment(
    c: &Connection,
    user_code: &str,
    approve: bool,
    user_id: i64,
    name: Option<&str>,
    now: i64,
) -> Result<bool> {
    Ok(c.execute(
        "UPDATE enrollments SET state = ?2, user_id = ?3, name = ?5
         WHERE user_code = ?1 AND state = 'pending' AND expires_at > ?4",
        params![
            user_code,
            if approve { "approved" } else { "denied" },
            user_id,
            now,
            name.unwrap_or_default()
        ],
    )? > 0)
}

pub fn delete_enrollment(c: &Connection, device_hash: &str) -> Result<()> {
    c.execute(
        "DELETE FROM enrollments WHERE device_hash = ?1",
        [device_hash],
    )?;
    Ok(())
}

#[derive(Clone, Debug)]
pub struct Host {
    pub id: i64,
    pub user_id: i64,
    pub name: String,
    pub info: HostInfo,
    pub fingerprint: String,
    pub activated: bool,
    pub claim_expires_at: i64,
    pub created_at: i64,
    pub last_seen_at: Option<i64>,
    pub kind: DeviceKind,
}

impl Host {
    pub fn usable(&self, now: i64) -> bool {
        self.activated || now < self.claim_expires_at
    }
}

const HOST_COLS: &str = "h.id, h.user_id, h.name, h.info, h.fingerprint, h.activated, h.claim_expires_at, h.created_at, h.last_seen_at, h.kind";
/// Column index where a row's joined user columns start after `HOST_COLS`.
const AFTER_HOST: usize = 10;

fn host_at(r: &Row, at: usize) -> rusqlite::Result<Host> {
    Ok(Host {
        id: r.get(at)?,
        user_id: r.get(at + 1)?,
        name: r.get(at + 2)?,
        info: serde_json::from_str(&r.get::<_, String>(at + 3)?).unwrap_or_default(),
        fingerprint: r.get(at + 4)?,
        activated: r.get(at + 5)?,
        claim_expires_at: r.get(at + 6)?,
        created_at: r.get(at + 7)?,
        last_seen_at: r.get(at + 8)?,
        kind: DeviceKind::parse(&r.get::<_, String>(at + 9)?),
    })
}

pub struct NewHost<'a> {
    pub id: i64,
    pub user_id: i64,
    pub name: &'a str,
    pub info: &'a HostInfo,
    pub host_key: &'a str,
    pub fingerprint: &'a str,
    pub credential_hash: &'a str,
    pub claim_expires_at: i64,
    pub kind: DeviceKind,
}

pub fn host_exists(c: &Connection, id: i64) -> Result<bool> {
    Ok(
        c.query_row("SELECT 1 FROM hosts WHERE id = ?1", [id], |_| Ok(()))
            .optional()?
            .is_some(),
    )
}

/// A phone never connects to `/relay/host`, which is what activates a computer,
/// so it is active from the start and is not purged when its claim expires.
pub fn insert_host(c: &Connection, h: &NewHost, now: i64) -> Result<()> {
    c.execute(
        "INSERT INTO hosts (id, user_id, name, info, host_key, fingerprint, credential_hash, claim_expires_at, created_at, kind, activated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            h.id,
            h.user_id,
            h.name,
            serde_json::to_string(h.info)?,
            h.host_key,
            h.fingerprint,
            h.credential_hash,
            h.claim_expires_at,
            now,
            h.kind.as_str(),
            h.kind == DeviceKind::Phone
        ],
    )?;
    Ok(())
}

pub fn host_by_credential(c: &Connection, credential_hash: &str) -> Result<Option<(Host, User)>> {
    Ok(c.query_row(
        &format!(
            "SELECT {HOST_COLS}, {USER_COLS} FROM hosts h JOIN users u ON u.id = h.user_id
             WHERE h.credential_hash = ?1"
        ),
        [credential_hash],
        |r| Ok((host_at(r, 0)?, user_at(r, AFTER_HOST)?)),
    )
    .optional()?)
}

pub fn host_by_id(c: &Connection, id: i64) -> Result<Option<Host>> {
    Ok(c.query_row(
        &format!("SELECT {HOST_COLS} FROM hosts h WHERE h.id = ?1"),
        [id],
        |r| host_at(r, 0),
    )
    .optional()?)
}

pub fn hosts_for_user(c: &Connection, user_id: i64) -> Result<Vec<Host>> {
    let mut stmt = c.prepare(&format!(
        "SELECT {HOST_COLS} FROM hosts h WHERE h.user_id = ?1 AND h.activated = 1 ORDER BY h.created_at"
    ))?;
    let rows = stmt.query_map([user_id], |r| host_at(r, 0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn host_ids_for_user(c: &Connection, user_id: i64) -> Result<Vec<i64>> {
    let mut stmt = c.prepare("SELECT id FROM hosts WHERE user_id = ?1")?;
    let rows = stmt.query_map([user_id], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn host_ids_with_key(c: &Connection, host_key: &str) -> Result<Vec<i64>> {
    let mut stmt = c.prepare("SELECT id FROM hosts WHERE host_key = ?1")?;
    let rows = stmt.query_map([host_key], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn delete_host(c: &Connection, id: i64, user_id: Option<i64>) -> Result<bool> {
    Ok(c.execute(
        "DELETE FROM hosts WHERE id = ?1 AND (?2 IS NULL OR user_id = ?2)",
        params![id, user_id],
    )? > 0)
}

pub fn rename_host(c: &Connection, id: i64, user_id: i64, name: &str) -> Result<bool> {
    Ok(c.execute(
        "UPDATE hosts SET name = ?3 WHERE id = ?1 AND user_id = ?2",
        params![id, user_id, name],
    )? > 0)
}

pub fn activate_host(c: &Connection, id: i64, info: &HostInfo, now: i64) -> Result<bool> {
    Ok(c.execute(
        "UPDATE hosts SET activated = 1, info = ?2, last_seen_at = ?3 WHERE id = ?1",
        params![id, serde_json::to_string(info)?, now],
    )? > 0)
}

pub fn touch_host(c: &Connection, id: i64, now: i64) -> Result<()> {
    c.execute(
        "UPDATE hosts SET last_seen_at = ?2 WHERE id = ?1",
        params![id, now],
    )?;
    Ok(())
}

/// How notifications reach the phone [host_id], if set on the web page.
pub fn notify_channel(c: &Connection, host_id: i64) -> Result<Option<Channel>> {
    let config: Option<String> = c
        .query_row(
            "SELECT config FROM notify_channels WHERE host_id = ?1",
            [host_id],
            |r| r.get(0),
        )
        .optional()?;
    // A channel this version cannot read counts as none.
    Ok(config.and_then(|c| serde_json::from_str(&c).ok()))
}

pub fn set_notify_channel(
    c: &Connection,
    host_id: i64,
    channel: Option<&Channel>,
    now: i64,
) -> Result<()> {
    match channel {
        Some(channel) => c.execute(
            "INSERT INTO notify_channels (host_id, config, updated_at) VALUES (?1, ?2, ?3)
             ON CONFLICT(host_id) DO UPDATE SET config = excluded.config, updated_at = excluded.updated_at",
            params![host_id, serde_json::to_string(channel)?, now],
        )?,
        None => c.execute("DELETE FROM notify_channels WHERE host_id = ?1", [host_id])?,
    };
    Ok(())
}

pub fn purge(c: &Connection, now: i64) -> Result<()> {
    c.execute("DELETE FROM web_sessions WHERE expires_at <= ?1", [now])?;
    c.execute("DELETE FROM enrollments WHERE expires_at <= ?1", [now])?;
    c.execute(
        "DELETE FROM hosts WHERE activated = 0 AND claim_expires_at <= ?1",
        [now],
    )?;
    Ok(())
}
