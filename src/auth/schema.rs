//! SQLite exclusivo para autenticacao: esquema v1, sem contas precriadas.
//! Nao armazena senhas nem tokens em texto claro.

use std::fs;
#[cfg(unix)]
use std::fs::OpenOptions;
use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

// 'RSTA' em hexadecimal: evita confundir o banco de autenticacao com outro SQLite.
const APPLICATION_ID: i64 = 0x5253_5441;
const SCHEMA_VERSION: i64 = 1;

const SQL_CREATE_SCHEMA: &str = r#"
    BEGIN IMMEDIATE;
    CREATE TABLE auth_accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE
            CHECK(length(username) BETWEEN 3 AND 64),
        password_hash TEXT NOT NULL
            CHECK(substr(password_hash, 1, 10) = '$argon2id$'),
        role TEXT NOT NULL CHECK(role IN ('viewer', 'editor', 'admin')),
        is_active INTEGER NOT NULL DEFAULT 1 CHECK(is_active IN (0, 1)),
        created_at INTEGER NOT NULL DEFAULT (unixepoch()),
        password_updated_at INTEGER
    );
    CREATE TABLE auth_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        account_id INTEGER NOT NULL REFERENCES auth_accounts(id) ON DELETE CASCADE,
        token_digest BLOB NOT NULL UNIQUE CHECK(length(token_digest) = 32),
        created_at INTEGER NOT NULL DEFAULT (unixepoch()),
        expires_at INTEGER NOT NULL,
        revoked_at INTEGER,
        CHECK(expires_at > created_at)
    );
    CREATE INDEX idx_auth_sessions_account ON auth_sessions(account_id);
    CREATE INDEX idx_auth_sessions_expiration ON auth_sessions(expires_at);
    CREATE TABLE auth_audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        occurred_at INTEGER NOT NULL DEFAULT (unixepoch()),
        account_id INTEGER REFERENCES auth_accounts(id) ON DELETE SET NULL,
        event_type TEXT NOT NULL CHECK(length(event_type) BETWEEN 1 AND 64),
        outcome TEXT NOT NULL CHECK(outcome IN ('success', 'failure', 'denied'))
    );
    PRAGMA application_id = 1381192769;
    PRAGMA user_version = 1;
    COMMIT;
"#;

/// Nova base v0 -> v1. Versoes desconhecidas e arquivos SQL de outras apps sao recusados.
pub(super) fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let app_id: i64 = conn.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if !(0..=SCHEMA_VERSION).contains(&version) {
        return Err(rusqlite::Error::InvalidParameterName(format!(
            "Versao de autenticacao nao suportada: {version}"
        )));
    }
    if app_id != 0 && app_id != APPLICATION_ID {
        return Err(rusqlite::Error::InvalidParameterName(
            "SQLite nao e um banco de autenticacao Rust-Server".into(),
        ));
    }
    if version == 0 {
        // Nao transformar um SQLite ja existente e desconhecido em banco de identidade.
        let existing_tables: i64 = conn.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        if existing_tables > 0 {
            return Err(rusqlite::Error::InvalidParameterName(
                "Arquivo SQLite sem versao contem tabelas preexistentes".into(),
            ));
        }
        conn.execute_batch(SQL_CREATE_SCHEMA)?;
    } else if app_id != APPLICATION_ID {
        return Err(rusqlite::Error::InvalidParameterName(
            "Schema de autenticacao sem identificacao valida".into(),
        ));
    }
    // Verifica antecipadamente que tabelas e colunas obrigatorias existem.
    conn.prepare("SELECT id, username, password_hash, role, is_active, created_at, password_updated_at FROM auth_accounts LIMIT 0")?;
    conn.prepare("SELECT id, account_id, token_digest, created_at, expires_at, revoked_at FROM auth_sessions LIMIT 0")?;
    conn.prepare(
        "SELECT id, occurred_at, account_id, event_type, outcome FROM auth_audit_events LIMIT 0",
    )?;
    let integrity: String = conn.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(rusqlite::Error::InvalidParameterName(
            "Banco de autenticacao falhou verificacao de integridade".into(),
        ));
    }
    Ok(())
}

pub(super) fn initialize_at(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if path.as_os_str().is_empty() || path == Path::new(":memory:") {
        return Err("RUST_SERVER_AUTH_DB_PATH precisa apontar para arquivo SQLite".into());
    }
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        #[cfg(unix)]
        {
            if !parent.exists() {
                // So a ultima pasta auth/ e criada com 0700. Pais ja precisam existir.
                fs::DirBuilder::new().mode(0o700).create(parent)?;
            }
            let meta = fs::symlink_metadata(parent)?;
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.permissions().mode() & 0o077 != 0
            {
                return Err(
                    "Diretorio do banco auth deve ser privado (0700) e nao pode ser symlink".into(),
                );
            }
        }
        #[cfg(not(unix))]
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    {
        if !path.exists() {
            // create_new evita seguir symlinks no momento da criacao.
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
            {
                Ok(_) => (),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(Box::new(e)),
            };
        }
        let meta = fs::symlink_metadata(path)?;
        if !meta.is_file()
            || meta.file_type().is_symlink()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err("Banco auth deve ser arquivo regular privado (0600), sem symlink".into());
        }
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags)?;
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.execute_batch(
        "PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;",
    )?;
    migrate(&conn)?;
    Ok(())
}
