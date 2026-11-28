//! SQLite persistence for account data and repository metadata.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

pub(crate) const DB_FILE: &str = "premier.db";
pub(crate) const AUTH_KEY: &str = "auth.key";
pub(crate) const SIDECARS: [&str; 3] = ["premier.db-wal", "premier.db-shm", "premier.db-journal"];
const AUTH_TABLES: [&str; 5] = ["users", "sessions", "tokens", "ssh_keys", "events"];
const REPO_KEY: &str = "default";
const SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS users (position INTEGER PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (position INTEGER PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS tokens (position INTEGER PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS ssh_keys (position INTEGER PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS events (position INTEGER PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS repo_state (repo_key TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS migrations (scope TEXT PRIMARY KEY);
    PRAGMA user_version = 1;";

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Scope {
    Auth,
    Repo,
}

impl Scope {
    fn name(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::Repo => "repo",
        }
    }
}

fn db_error(error: rusqlite::Error) -> String {
    format!("SQLite state error: {error}")
}

fn json_error(error: serde_json::Error) -> String {
    format!("invalid control-plane state: {error}")
}

fn legacy<T: DeserializeOwned + Default>(dir: &Path, name: &str) -> Result<T, String> {
    let path = dir.join(name);
    match fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| format!("{} is corrupt: {e}", path.display())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("read {} failed: {e}", path.display())),
    }
}

pub(crate) struct StateDb(Connection);

impl StateDb {
    pub(crate) fn open(dir: &Path) -> Result<Self, String> {
        premier_secrets::create_state_dir(dir)
            .map_err(|e| format!("create SQLite state directory failed: {e}"))?;
        let path = dir.join(DB_FILE);
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
                    return Err("SQLite state path is not a regular file".to_owned());
                }
            }
            Err(e) => return Err(format!("create SQLite state file failed: {e}")),
        }
        let mut conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(db_error)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(db_error)?;
        let journal: String = conn
            .pragma_query_value(None, "journal_mode", |r| r.get(0))
            .map_err(db_error)?;
        if journal != "wal" {
            // SQLite can refuse WAL without returning an error on unsupported filesystems.
            let mode: String = conn
                .query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0))
                .map_err(db_error)?;
            if mode != "wal" {
                return Err("could not enable SQLite WAL mode".to_owned());
            }
        }
        conn.execute_batch("PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;")
            .map_err(db_error)?;
        match Self::version(&conn)? {
            0 => {
                let tx = conn
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .map_err(db_error)?;
                tx.execute_batch(SCHEMA).map_err(db_error)?;
                tx.commit().map_err(db_error)?;
            }
            1 => {}
            version => return Err(format!("unsupported SQLite schema version {version}")),
        }
        Ok(Self(conn))
    }

    fn version(conn: &Connection) -> Result<i64, String> {
        conn.pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(db_error)
    }

    fn has_scope(conn: &Connection, scope: Scope) -> Result<bool, String> {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM migrations WHERE scope = ?1)",
            [scope.name()],
            |row| row.get(0),
        )
        .map_err(db_error)
    }

    fn mark_scope(conn: &Connection, scope: Scope) -> Result<(), String> {
        conn.execute(
            "INSERT OR IGNORE INTO migrations (scope) VALUES (?1)",
            [scope.name()],
        )
        .map_err(db_error)?;
        Ok(())
    }

    pub(crate) fn probe_write(&mut self) -> Result<(), String> {
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        tx.execute("INSERT INTO migrations (scope) VALUES ('readiness')", [])
            .map_err(db_error)?;
        tx.rollback().map_err(db_error)
    }

    pub(crate) fn repo_state<T: Serialize + DeserializeOwned + Default>(
        &mut self,
        dir: &Path,
        save: Option<&T>,
    ) -> Result<T, String> {
        let read = |conn: &Connection| -> Result<T, String> {
            let row: String = conn
                .query_row(
                    "SELECT data FROM repo_state WHERE repo_key = ?1",
                    [REPO_KEY],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            serde_json::from_str(&row).map_err(json_error)
        };
        if save.is_none() && Self::has_scope(&self.0, Scope::Repo)? {
            return read(&self.0);
        }
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let imported;
        let state = match save {
            Some(state) => state,
            None if !Self::has_scope(&tx, Scope::Repo)? => {
                imported = legacy(dir, "state.json")?;
                &imported
            }
            None => return read(&tx),
        };
        let json = serde_json::to_string(state).map_err(json_error)?;
        tx.execute(
            "INSERT INTO repo_state (repo_key, data) VALUES (?1, ?2)
             ON CONFLICT(repo_key) DO UPDATE SET data = excluded.data",
            params![REPO_KEY, json],
        )
        .map_err(db_error)?;
        Self::mark_scope(&tx, Scope::Repo)?;
        tx.commit().map_err(db_error)?;
        if save.is_some() {
            Ok(T::default())
        } else {
            serde_json::from_str(&json).map_err(json_error)
        }
    }

    fn read_auth_tables(conn: &Connection, tables: &[&str]) -> Result<Map<String, Value>, String> {
        let mut record = Map::new();
        for &table in tables {
            let mut query = conn
                .prepare(&format!("SELECT data FROM {table} ORDER BY position"))
                .map_err(db_error)?;
            let rows = query
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(db_error)?;
            let mut values = Vec::new();
            for row in rows {
                values.push(serde_json::from_str(&row.map_err(db_error)?).map_err(json_error)?);
            }
            record.insert(table.to_owned(), Value::Array(values));
        }
        Ok(record)
    }

    /// A snapshot of credentials and accounts. Missing or unmigrated state goes through the
    /// normal write transaction, so the legacy JSON import still happens before authentication.
    pub(crate) fn read_auth_credentials<T: DeserializeOwned>(
        dir: &Path,
        bearer: bool,
    ) -> Result<Option<T>, String> {
        let path = dir.join(DB_FILE);
        match fs::symlink_metadata(&path) {
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("read SQLite state failed: {e}")),
            Ok(meta) if !meta.is_file() => {
                return Err("SQLite state path is not a regular file".into());
            }
            Ok(_) => {}
        }
        let mut conn = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(db_error)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(db_error)?;
        let tx = conn.transaction().map_err(db_error)?;
        match Self::version(&tx)? {
            0 => return Ok(None),
            1 => {}
            version => return Err(format!("unsupported SQLite schema version {version}")),
        }
        if !Self::has_scope(&tx, Scope::Auth)? {
            return Ok(None);
        }
        let mut data =
            Self::read_auth_tables(&tx, &["users", if bearer { "tokens" } else { "sessions" }])?;
        crypt_users(&mut data, dir, false)?;
        serde_json::from_value(Value::Object(data))
            .map(Some)
            .map_err(json_error)
    }

    pub(crate) fn auth_transaction<T, R>(
        &mut self,
        dir: &Path,
        change: impl FnOnce(&mut T) -> (R, bool),
    ) -> Result<R, String>
    where
        T: Serialize + DeserializeOwned + Default,
    {
        if !Self::has_scope(&self.0, Scope::Auth)? {
            // The first commit must be durable before removing the plaintext legacy file.
            self.0
                .pragma_update(None, "synchronous", "FULL")
                .map_err(db_error)?;
        }
        let tx = self
            .0
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let migrated = Self::has_scope(&tx, Scope::Auth)?;
        let (mut data, original, original_users) = if migrated {
            let original = Self::read_auth_tables(&tx, &AUTH_TABLES)?;
            let mut decoded = original.clone();
            crypt_users(&mut decoded, dir, false)?;
            let original_users = decoded.get("users").cloned();
            (
                serde_json::from_value(Value::Object(decoded)).map_err(json_error)?,
                Some(original),
                original_users,
            )
        } else {
            (legacy(dir, "auth.json")?, None, None)
        };
        let (result, dirty) = change(&mut data);
        if dirty || !migrated {
            let mut data: Map<String, Value> = serde_json::to_value(data)
                .and_then(serde_json::from_value)
                .map_err(json_error)?;
            if original_users.as_ref() == data.get("users") {
                if let Some(users) = original.as_ref().and_then(|before| before.get("users")) {
                    data.insert("users".to_owned(), users.clone());
                }
            } else {
                crypt_users(&mut data, dir, true)?;
            }
            for table in AUTH_TABLES {
                let values = data
                    .get(table)
                    .and_then(Value::as_array)
                    .ok_or("missing table in auth state")?;
                if original
                    .as_ref()
                    .and_then(|data| data.get(table))
                    .and_then(Value::as_array)
                    == Some(values)
                {
                    continue;
                }
                tx.execute(&format!("DELETE FROM {table}"), [])
                    .map_err(db_error)?;
                let mut insert = tx
                    .prepare(&format!(
                        "INSERT INTO {table} (position, data) VALUES (?1, ?2)"
                    ))
                    .map_err(db_error)?;
                for (position, value) in values.iter().enumerate() {
                    let pos =
                        i64::try_from(position).map_err(|_| "row position overflow".to_owned())?;
                    insert
                        .execute(params![pos, value.to_string()])
                        .map_err(db_error)?;
                }
            }
            Self::mark_scope(&tx, Scope::Auth)?;
        }
        tx.commit().map_err(db_error)?;
        if !migrated {
            match fs::remove_file(dir.join("auth.json")) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => tracing::warn!(error = %e, "could not remove migrated legacy auth file"),
            }
        }
        Ok(result)
    }

    pub(crate) fn snapshot_has_scope(path: &Path, scope: Scope) -> Result<bool, String> {
        if !fs::symlink_metadata(path).is_ok_and(|m| m.is_file()) {
            return Err("SQLite snapshot is not a regular file".to_owned());
        }
        let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(db_error)?;
        if Self::version(&conn)? != 1 {
            return Err("unsupported SQLite snapshot schema".to_owned());
        }
        Self::has_scope(&conn, scope)
    }

    /// Snapshot committed state, including pages still resident in the WAL.
    pub(crate) fn snapshot(source: &Path, destination: &Path) -> Result<(), String> {
        if !fs::symlink_metadata(source).is_ok_and(|m| m.is_file()) {
            return Err("SQLite backup source is not a regular file".to_owned());
        }
        let conn = Connection::open_with_flags(source, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(db_error)?;
        conn.busy_timeout(Duration::from_secs(5))
            .map_err(db_error)?;
        let destination = destination
            .to_str()
            .ok_or("SQLite backup path is not UTF-8")?;
        conn.execute("VACUUM INTO ?1", [destination])
            .map_err(db_error)?;
        Ok(())
    }

    /// Copy one part of a staged backup into its destination without mixing account and repo data.
    pub(crate) fn import_scope(&mut self, source: &Path, scope: Scope) -> Result<bool, String> {
        let source = source.to_str().ok_or("SQLite restore path is not UTF-8")?;
        self.0
            .execute("ATTACH DATABASE ?1 AS backup", [source])
            .map_err(db_error)?;
        let result = (|| {
            let version: i64 = self
                .0
                .query_row("PRAGMA backup.user_version", [], |r| r.get(0))
                .map_err(db_error)?;
            if version != 1 {
                return Err(format!(
                    "unsupported SQLite backup schema version {version}"
                ));
            }
            let present: bool = self
                .0
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM backup.migrations WHERE scope = ?1)",
                    [scope.name()],
                    |r| r.get(0),
                )
                .map_err(db_error)?;
            if !present {
                return Ok(false);
            }
            let tables: &[&str] = match scope {
                Scope::Auth => &AUTH_TABLES,
                Scope::Repo => &["repo_state"],
            };
            let tx = self
                .0
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(db_error)?;
            for table in tables {
                // Names come only from the schema constants above.
                tx.execute_batch(&format!(
                    "DELETE FROM main.{table}; INSERT INTO main.{table} SELECT * FROM backup.{table};"
                )).map_err(db_error)?;
            }
            Self::mark_scope(&tx, scope)?;
            tx.commit().map_err(db_error)?;
            Ok(true)
        })();
        let detach = self
            .0
            .execute("DETACH DATABASE backup", [])
            .map_err(db_error);
        result.and_then(|copied| detach.map(|_| copied))
    }
}

fn auth_cipher(dir: &Path, create: bool) -> Result<Aes256Gcm, String> {
    let key_path = dir.join(AUTH_KEY);
    let key = match fs::read(&key_path) {
        Ok(bytes) => Zeroizing::new(bytes),
        Err(e) if create && e.kind() == ErrorKind::NotFound => {
            let key = Zeroizing::new(crate::auth::random_bytes(32));
            let temp = tempfile::NamedTempFile::new_in(dir)
                .map_err(|e| format!("create temporary auth key failed: {e}"))?;
            premier_secrets::write_private(temp.path(), &key)
                .map_err(|e| format!("write auth key failed: {e}"))?;
            temp.as_file()
                .sync_all()
                .map_err(|e| format!("sync auth key failed: {e}"))?;
            temp.persist_noclobber(&key_path)
                .map_err(|e| format!("install auth key failed: {e}"))?;
            key
        }
        Err(e) => return Err(format!("read auth key failed: {e}")),
    };
    Aes256Gcm::new_from_slice(&key).map_err(|_| "invalid auth key length".to_owned())
}

fn crypt_users(data: &mut Map<String, Value>, dir: &Path, encrypt: bool) -> Result<(), String> {
    let users = data
        .get_mut("users")
        .and_then(Value::as_array_mut)
        .ok_or("missing users")?;
    let mut cipher = None;
    for user in users {
        let username = user
            .get("username")
            .and_then(Value::as_str)
            .ok_or("missing username")?
            .to_owned();
        for field in ["totp_secret", "totp_pending"] {
            let Some(value) = user.get_mut(field).filter(|v| !v.is_null()) else {
                continue;
            };
            let raw = value.as_str().ok_or("invalid stored TOTP field")?;
            let cipher = match &cipher {
                Some(cipher) => cipher,
                None => cipher.insert(auth_cipher(dir, encrypt)?),
            };
            let aad = format!("premier-auth-v1:{field}:{username}");
            let transformed = if encrypt {
                let nonce: [u8; 12] = crate::auth::random_bytes(12)
                    .try_into()
                    .map_err(|_| "invalid nonce length")?;
                let ciphertext = cipher
                    .encrypt(
                        &Nonce::from(nonce),
                        Payload {
                            msg: raw.as_bytes(),
                            aad: aad.as_bytes(),
                        },
                    )
                    .map_err(|_| "TOTP encryption failed")?;
                let mut encoded = nonce.to_vec();
                encoded.extend(ciphertext);
                BASE64.encode(encoded)
            } else {
                let encoded = BASE64
                    .decode(raw)
                    .map_err(|_| "invalid encrypted TOTP data")?;
                let (nonce, ciphertext) = encoded
                    .split_at_checked(12)
                    .ok_or("invalid encrypted TOTP data")?;
                let nonce: [u8; 12] = nonce.try_into().map_err(|_| "invalid TOTP nonce")?;
                let plaintext = cipher
                    .decrypt(
                        &Nonce::from(nonce),
                        Payload {
                            msg: ciphertext,
                            aad: aad.as_bytes(),
                        },
                    )
                    .map_err(|_| "TOTP decryption failed")?;
                String::from_utf8(plaintext).map_err(|_| "invalid decrypted TOTP data")?
            };
            *value = Value::String(transformed);
        }
    }
    Ok(())
}
