//! Testes unitarios: RBAC definido, SQLite independente e migracao de esquema.

use super::policy::{Decision, Identity, Operation, Role, authorize};
use super::schema::migrate;
use rusqlite::Connection;

fn account(id: u64, role: Role) -> Identity {
    Identity {
        account_id: id,
        role,
        active: true,
    }
}

#[test]
fn anonymous_is_unauthenticated() {
    assert_eq!(
        authorize(None, Operation::ReadUsers),
        Decision::Unauthenticated
    );
    assert_eq!(
        authorize(None, Operation::DeleteUsers),
        Decision::Unauthenticated
    );
}

#[test]
fn disabled_and_invalid_id_are_forbidden() {
    let mut editor = account(4, Role::Editor);
    editor.active = false;
    assert_eq!(
        authorize(Some(&editor), Operation::ReadUsers),
        Decision::Forbidden
    );
    let bad_id = account(0, Role::Admin);
    assert_eq!(
        authorize(Some(&bad_id), Operation::ReadUsers),
        Decision::Forbidden
    );
}

#[test]
fn viewer_is_read_only() {
    let user = account(1, Role::Viewer);
    assert_eq!(
        authorize(Some(&user), Operation::ReadUsers),
        Decision::Allow
    );
    for operation in [
        Operation::CreateUsers,
        Operation::ModifyUsers,
        Operation::DeleteUsers,
        Operation::ManageCredentials,
    ] {
        assert_eq!(authorize(Some(&user), operation), Decision::Forbidden);
    }
}

#[test]
fn editor_can_write_but_not_delete_or_manage_identities() {
    let user = account(2, Role::Editor);
    for operation in [
        Operation::ReadUsers,
        Operation::CreateUsers,
        Operation::ModifyUsers,
    ] {
        assert_eq!(authorize(Some(&user), operation), Decision::Allow);
    }
    for operation in [Operation::DeleteUsers, Operation::ManageCredentials] {
        assert_eq!(authorize(Some(&user), operation), Decision::Forbidden);
    }
}

#[test]
fn admin_can_access_all_defined_operations() {
    let user = account(3, Role::Admin);
    for operation in [
        Operation::ReadUsers,
        Operation::CreateUsers,
        Operation::ModifyUsers,
        Operation::DeleteUsers,
        Operation::ManageCredentials,
    ] {
        assert_eq!(authorize(Some(&user), operation), Decision::Allow);
    }
}

#[test]
fn creates_empty_versioned_auth_schema() {
    let conn = Connection::open_in_memory().expect("SQLite em memoria");
    migrate(&conn).expect("schema v1");
    let version: i64 = conn
        .pragma_query_value(None, "user_version", |r| r.get(0))
        .unwrap();
    assert_eq!(version, 1);
    let total: i64 = conn
        .query_row("SELECT count(*) FROM auth_accounts", [], |r| r.get(0))
        .unwrap();
    assert_eq!(total, 0); // nenhuma conta admin padrao
    migrate(&conn).expect("migracao idempotente");
}

#[test]
fn rejects_unrelated_database_and_future_schema() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE unrelated (id INTEGER)")
        .unwrap();
    assert!(migrate(&conn).is_err());
    let future = Connection::open_in_memory().unwrap();
    future.execute_batch("PRAGMA user_version = 99").unwrap();
    assert!(migrate(&future).is_err());
}

#[test]
fn sqlite_refuses_plaintext_passwords_and_unknown_roles() {
    let conn = Connection::open_in_memory().unwrap();
    migrate(&conn).unwrap();
    let plain = conn.execute(
        "INSERT INTO auth_accounts (username, password_hash, role) VALUES (?1, ?2, ?3)",
        ("alice", "plain-password", "admin"),
    );
    assert!(plain.is_err());
    let role = conn.execute(
        "INSERT INTO auth_accounts (username, password_hash, role) VALUES (?1, ?2, ?3)",
        ("alice", "$argon2id$placeholder", "superuser"),
    );
    assert!(role.is_err());
}

#[test]
fn session_digest_and_foreign_key_are_constrained() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA foreign_keys = ON").unwrap();
    migrate(&conn).unwrap();
    let inserted = conn.execute(
        "INSERT INTO auth_sessions (account_id, token_digest, expires_at) VALUES (1, x'0001', unixepoch()+3600)", []
    );
    assert!(inserted.is_err());
    let missing_account = conn.execute(
        "INSERT INTO auth_sessions (account_id, token_digest, expires_at) VALUES (1, zeroblob(32), unixepoch()+3600)", []
    );
    assert!(missing_account.is_err());
}
