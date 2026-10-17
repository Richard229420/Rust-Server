//! Fase 6.1: infraestrutura de identidade, sem endpoints de login.
//! IMPORTANTE: a politica abaixo ainda nao e aplicada ao CRUD REST.

use std::path::{Path, PathBuf};

#[path = "auth/schema.rs"]
mod schema;
// Sera conectada ao middleware/handlers nas fases 6.2 e 6.3.
#[allow(dead_code)]
#[path = "auth/policy.rs"]
mod policy;

/// Banco de identidades separado do cadastro legado de /api/v1/users.
/// Se o banco REST for temporario (testes), o banco de identidade sera temporario tambem.
fn database_path() -> PathBuf {
    if let Some(path) = std::env::var_os("RUST_SERVER_AUTH_DB_PATH") {
        return PathBuf::from(path);
    }
    let users = std::env::var_os("RUST_SERVER_DB_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("data/users.sqlite3"));
    users
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("auth")
        .join("auth.sqlite3")
}

/// Falha antes do bind da porta HTTP se o schema de identidades for inconsistente.
pub(super) fn initialize() -> Result<(), Box<dyn std::error::Error>> {
    schema::initialize_at(&database_path())
}

#[cfg(test)]
#[path = "auth/tests.rs"]
mod tests;
