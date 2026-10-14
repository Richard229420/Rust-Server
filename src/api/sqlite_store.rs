//! Persistencia SQLite para a API REST do laboratorio.
//! Uma conexao por processo, protegida no modulo pai por Mutex<Store>.

use std::fs;
use std::path::Path;
use std::time::Duration;

use rusqlite::{
    Connection, Error as SqlError, ErrorCode, OpenFlags, OptionalExtension, Row,
    TransactionBehavior, params,
};

use super::{MAX_USERS, User};

#[derive(Debug)]
pub(super) enum StoreError {
    Sql(SqlError),
    EmailConflict,
    Capacity,
}

impl From<SqlError> for StoreError {
    fn from(error: SqlError) -> Self {
        Self::Sql(error)
    }
}

pub(super) struct Store {
    conn: Connection,
}

fn parse_user(row: &Row<'_>) -> rusqlite::Result<User> {
    let id: i64 = row.get(0)?;
    let id = u64::try_from(id).map_err(|_| SqlError::IntegralValueOutOfRange(0, id))?;
    Ok(User {
        id,
        name: row.get(1)?,
        email: row.get(2)?,
    })
}

fn is_unique_violation(error: &SqlError) -> bool {
    matches!(error, SqlError::SqliteFailure(code, _) if code.code == ErrorCode::ConstraintViolation && code.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE)
}

impl Store {
    pub(super) fn open_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if path.as_os_str().is_empty() || path == Path::new(":memory:") {
            return Err("RUST_SERVER_DB_PATH deve apontar para um arquivo SQLite valido".into());
        }
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        // Nao interpreta caminhos fornecidos pelo operador como URIs SQLite.
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        let conn = Connection::open_with_flags(path, flags)?;
        Self::initialize(conn, true).map_err(Into::into)
    }

    #[cfg(test)]
    pub(super) fn in_memory() -> Self {
        Self::initialize(
            Connection::open_in_memory().expect("SQLite em memoria"),
            false,
        )
        .expect("Criacao do schema SQLite em memoria")
    }

    fn initialize(conn: Connection, on_disk: bool) -> rusqlite::Result<Self> {
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        if on_disk {
            conn.execute_batch("PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL;")?;
        }
        let version: i64 = conn.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if version != 0 && version != 1 {
            return Err(SqlError::InvalidParameterName(format!(
                "Versao SQLite nao suportada: {version}"
            )));
        }
        // Versao 1: campo email unico (sem diferenciar maiusculas), ID nunca reutilizado.
        // BEGIN...COMMIT aplica schema e versao como uma unica transacao.
        if version == 0 {
            conn.execute_batch(
                "BEGIN IMMEDIATE;
                 CREATE TABLE IF NOT EXISTS api_users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   name TEXT NOT NULL CHECK(length(name) BETWEEN 1 AND 80),
                   email TEXT NOT NULL COLLATE NOCASE UNIQUE CHECK(length(email) BETWEEN 3 AND 254)
                 );
                 PRAGMA user_version = 1;
                 COMMIT;",
            )?;
        }
        // Detecta de modo antecipado bancos inconsistentes ou incompletos.
        conn.prepare("SELECT id, name, email FROM api_users LIMIT 0")?;
        Ok(Self { conn })
    }

    pub(super) fn list(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<(Vec<User>, usize), StoreError> {
        let total: i64 = self
            .conn
            .query_row("SELECT count(*) FROM api_users", [], |row| row.get(0))?;
        let limit = i64::try_from(limit).unwrap_or(i64::MAX);
        let offset = i64::try_from(offset).unwrap_or(i64::MAX);
        let mut statement = self
            .conn
            .prepare("SELECT id, name, email FROM api_users ORDER BY id LIMIT ?1 OFFSET ?2")?;
        let users = statement
            .query_map(params![limit, offset], parse_user)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok((users, usize::try_from(total).unwrap_or(usize::MAX)))
    }

    pub(super) fn get(&self, id: u64) -> Result<Option<User>, StoreError> {
        let Ok(id) = i64::try_from(id) else {
            return Ok(None);
        };
        Ok(self
            .conn
            .query_row(
                "SELECT id, name, email FROM api_users WHERE id = ?1",
                params![id],
                parse_user,
            )
            .optional()?)
    }

    pub(super) fn create(&mut self, name: &str, email: &str) -> Result<User, StoreError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: i64 = tx.query_row("SELECT count(*) FROM api_users", [], |row| row.get(0))?;
        if count >= i64::try_from(MAX_USERS).unwrap_or(i64::MAX) {
            return Err(StoreError::Capacity);
        }
        match tx.execute(
            "INSERT INTO api_users (name, email) VALUES (?1, ?2)",
            params![name, email],
        ) {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => return Err(StoreError::EmailConflict),
            Err(error) => return Err(error.into()),
        }
        let id = tx.last_insert_rowid();
        tx.commit()?;
        let id = u64::try_from(id).map_err(|_| StoreError::Capacity)?;
        Ok(User {
            id,
            name: name.to_owned(),
            email: email.to_owned(),
        })
    }

    pub(super) fn update(
        &mut self,
        id: u64,
        name: Option<String>,
        email: Option<String>,
    ) -> Result<Option<User>, StoreError> {
        let Ok(id_int) = i64::try_from(id) else {
            return Ok(None);
        };
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = tx
            .query_row(
                "SELECT id, name, email FROM api_users WHERE id = ?1",
                params![id_int],
                parse_user,
            )
            .optional()?;
        let Some(existing) = existing else {
            return Ok(None);
        };
        let user = User {
            id,
            name: name.unwrap_or(existing.name),
            email: email.unwrap_or(existing.email),
        };
        match tx.execute(
            "UPDATE api_users SET name = ?1, email = ?2 WHERE id = ?3",
            params![user.name, user.email, id_int],
        ) {
            Ok(_) => {}
            Err(error) if is_unique_violation(&error) => return Err(StoreError::EmailConflict),
            Err(error) => return Err(error.into()),
        }
        tx.commit()?;
        Ok(Some(user))
    }

    pub(super) fn delete(&mut self, id: u64) -> Result<bool, StoreError> {
        let Ok(id) = i64::try_from(id) else {
            return Ok(false);
        };
        Ok(self
            .conn
            .execute("DELETE FROM api_users WHERE id = ?1", params![id])?
            != 0)
    }
}
