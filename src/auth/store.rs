//! Operacoes do banco de identidade. Sem SQL no cadastro REST legado.
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OpenFlags, OptionalExtension, params};

use super::credentials;

pub(super) const SESSION_TTL_SECS: i64 = 3600;

#[derive(Clone, Debug)]
pub(super) struct Principal {
    pub(super) id: i64,
    pub(super) username: String,
    pub(super) role: String,
    pub(super) expires_at: i64,
}

pub(super) struct Session {
    pub(super) token: String,
    pub(super) principal: Principal,
}

fn now() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())
        .and_then(|time| i64::try_from(time.as_secs()).map_err(|e| e.to_string()))
}

fn open(path: &Path) -> Result<Connection, String> {
    if !path.is_file() {
        return Err("Banco de identidades ausente".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_file()
            || metadata.permissions().mode() & 0o077 != 0
        {
            return Err("Permissoes invalidas do banco auth".into());
        }
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags).map_err(|e| e.to_string())?;
    conn.busy_timeout(Duration::from_secs(5))
        .map_err(|e| e.to_string())?;
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .map_err(|e| e.to_string())?;
    Ok(conn)
}

pub(super) fn bootstrap_admin(path: &Path, username: &str, password: &str) -> Result<(), String> {
    if !credentials::username_valid(username) {
        return Err("Usuario: 3-64 caracteres ASCII (letras, numeros, ponto, _, -)".into());
    }
    let password_hash = credentials::hash_password(password)?;
    let mut conn = open(path)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let count: i64 = tx
        .query_row("SELECT count(*) FROM auth_accounts", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if count != 0 {
        return Err(
            "Bootstrap permitido somente sem contas; nunca sobrescreve administradores".into(),
        );
    }
    tx.execute(
        "INSERT INTO auth_accounts(username, password_hash, role, password_updated_at) VALUES (?1, ?2, 'admin', unixepoch())",
        params![username, password_hash],
    )
    .map_err(|e| e.to_string())?;
    audit(&tx, None, "bootstrap", "success")?;
    tx.commit().map_err(|e| e.to_string())
}

pub(super) fn reset_password(path: &Path, username: &str, password: &str) -> Result<(), String> {
    if !credentials::username_valid(username) {
        return Err("Nome de usuario invalido".into());
    }
    let password_hash = credentials::hash_password(password)?;
    let mut conn = open(path)?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    let changed = tx
        .execute(
            "UPDATE auth_accounts SET password_hash = ?1, password_updated_at = unixepoch() WHERE username = ?2",
            params![password_hash, username],
        )
        .map_err(|e| e.to_string())?;
    if changed != 1 {
        return Err("Conta nao encontrada".into());
    }
    tx.execute(
        "UPDATE auth_sessions SET revoked_at = unixepoch() WHERE account_id = (SELECT id FROM auth_accounts WHERE username = ?1) AND revoked_at IS NULL",
        params![username],
    )
    .map_err(|e| e.to_string())?;
    audit(&tx, None, "password_reset", "success")?;
    tx.commit().map_err(|e| e.to_string())
}

fn audit(
    conn: &Connection,
    account_id: Option<i64>,
    event: &str,
    outcome: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT INTO auth_audit_events(account_id, event_type, outcome) VALUES (?1, ?2, ?3)",
        params![account_id, event, outcome],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub(super) fn login(
    path: &Path,
    username: &str,
    password: &str,
) -> Result<Option<Session>, String> {
    let mut conn = open(path)?;
    let stored: Option<(i64, String, String, String, bool)> = conn
        .query_row(
            "SELECT id, username, password_hash, role, is_active FROM auth_accounts WHERE username = ?1",
            params![username],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get::<_, i64>(4)? == 1)),
        )
        .optional()
        .map_err(|e| e.to_string())?;
    let valid = if let Some((_, _, ref hashed, _, _)) = stored {
        credentials::verify_password(password, hashed)
    } else {
        credentials::spend_dummy_hash(password);
        false
    };
    let account = match (stored, valid) {
        (Some((id, name, _, role, true)), true) => (id, name, role),
        _ => {
            audit(&conn, None, "login", "failure")?;
            return Ok(None);
        }
    };
    let (token, digest) = credentials::issue_token();
    let expires_at = now()?
        .checked_add(SESSION_TTL_SECS)
        .ok_or("Expiracao fora do intervalo")?;
    let tx = conn.transaction().map_err(|e| e.to_string())?;
    // Reconfere a conta dentro da escrita para nao criar sessao de conta desativada.
    let inserted = tx.execute(
        "INSERT INTO auth_sessions(account_id, token_digest, created_at, expires_at) SELECT id, ?1, ?2, ?3 FROM auth_accounts WHERE id = ?4 AND is_active = 1",
        params![digest.as_slice(), expires_at - SESSION_TTL_SECS, expires_at, account.0],
    )
    .map_err(|e| e.to_string())?;
    if inserted != 1 {
        return Ok(None);
    }
    audit(&tx, Some(account.0), "login", "success")?;
    tx.commit().map_err(|e| e.to_string())?;
    Ok(Some(Session {
        token,
        principal: Principal {
            id: account.0,
            username: account.1,
            role: account.2,
            expires_at,
        },
    }))
}

pub(super) fn authenticate(path: &Path, token: &str) -> Result<Option<Principal>, String> {
    if !credentials::valid_token_format(token) {
        return Ok(None);
    }
    let conn = open(path)?;
    let digest = credentials::digest_token(token);
    conn.query_row(
        "SELECT a.id, a.username, a.role, s.expires_at FROM auth_sessions s JOIN auth_accounts a ON a.id = s.account_id WHERE s.token_digest = ?1 AND s.revoked_at IS NULL AND s.expires_at > ?2 AND a.is_active = 1",
        params![digest.as_slice(), now()?],
        |r| {
            Ok(Principal {
                id: r.get(0)?,
                username: r.get(1)?,
                role: r.get(2)?,
                expires_at: r.get(3)?,
            })
        },
    )
    .optional()
    .map_err(|e| e.to_string())
}

pub(super) fn revoke(path: &Path, token: &str) -> Result<bool, String> {
    if !credentials::valid_token_format(token) {
        return Ok(false);
    }
    let conn = open(path)?;
    let digest = credentials::digest_token(token);
    let changed = conn
        .execute(
            "UPDATE auth_sessions SET revoked_at = ?1 WHERE token_digest = ?2 AND revoked_at IS NULL AND expires_at > ?1 AND account_id IN (SELECT id FROM auth_accounts WHERE is_active = 1)",
            params![now()?, digest.as_slice()],
        )
        .map_err(|e| e.to_string())?;
    if changed == 1 {
        // Auditoria nao inclui token, nome de usuario ou senha.
        let _ = audit(&conn, None, "logout", "success");
    }
    Ok(changed == 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    #[test]
    fn bootstrap_login_revoke_and_reset_on_temp_file() {
        let root = std::env::temp_dir().join(format!(
            "rust-auth62-{}-{}",
            std::process::id(),
            now().unwrap()
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let db = root.join("identities.sqlite3");
        let conn = Connection::open(&db).unwrap();
        super::super::schema::migrate(&conn).unwrap();
        drop(conn);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        bootstrap_admin(&db, "localadmin", "senha-segura-123456").unwrap();
        assert!(bootstrap_admin(&db, "outroadmin", "senha-segura-123456").is_err());
        assert!(
            login(&db, "localadmin", "senha-errada-123456")
                .unwrap()
                .is_none()
        );
        let session = login(&db, "LOCALADMIN", "senha-segura-123456")
            .unwrap()
            .unwrap();
        assert_eq!(session.principal.role, "admin");
        assert!(authenticate(&db, &session.token).unwrap().is_some());
        assert!(revoke(&db, &session.token).unwrap());
        assert!(authenticate(&db, &session.token).unwrap().is_none());
        let new_session = login(&db, "localadmin", "senha-segura-123456")
            .unwrap()
            .unwrap();
        reset_password(&db, "localadmin", "uma-nova-senha-123456").unwrap();
        assert!(authenticate(&db, &new_session.token).unwrap().is_none());
        assert!(
            login(&db, "localadmin", "senha-segura-123456")
                .unwrap()
                .is_none()
        );
        assert!(
            login(&db, "localadmin", "uma-nova-senha-123456")
                .unwrap()
                .is_some()
        );
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_dir(&root);
    }
}
