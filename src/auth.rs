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
    schema::initialize_at(&database_path())?;
    // Retencao de eventos antigos executada apenas no startup; nunca apagar contas/sessoes.
    security64::prune(&database_path()).map_err(std::io::Error::other)?;
    Ok(())
}

#[cfg(test)]
#[path = "auth/tests.rs"]
mod tests;

// Fase 6.2: credenciais, sessoes e despacho local /api/v1/auth/*.
#[path = "auth/credentials.rs"]
mod credentials;
#[path = "auth/http.rs"]
mod http;
#[allow(dead_code)] // Comandos administrativos usados no binario auth_admin, nao no servidor.
#[path = "auth/store.rs"]
mod store;

#[allow(dead_code)] // Apenas utilitario local.
pub(super) fn database_file() -> PathBuf {
    database_path()
}

#[allow(dead_code)] // Apenas utilitario local.
pub(super) fn bootstrap_admin(name: &str, password: &str) -> Result<(), String> {
    store::bootstrap_admin(&database_path(), name, password)
}

#[allow(dead_code)] // Apenas utilitario local.
pub(super) fn reset_account_password(name: &str, password: &str) -> Result<(), String> {
    store::reset_password(&database_path(), name, password)
}

pub(super) fn handle_http(
    method: &str,
    path: &str,
    headers: &std::collections::HashMap<String, String>,
    body: &[u8],
    raw_head: &[u8],
    peer_ip: &str,
) -> Option<http::AuthResponse> {
    http::handle(method, path, headers, body, raw_head, peer_ip)
}

// Fase 6.3: RBAC aplicado em /api/v1/users antes do CRUD.
#[allow(dead_code)] // auth_admin compila auth.rs mas nao possui roteamento HTTP.
#[path = "auth/guard.rs"]
mod guard;

#[allow(dead_code)] // Utilizado pelo servidor; nao pelo binario auth_admin.
pub(super) fn guard_users(
    method: &str,
    target: &str,
    headers: &std::collections::HashMap<String, String>,
    raw_head: &[u8],
) -> Option<http::AuthResponse> {
    guard::enforce(method, target, headers, raw_head)
}

// Fase 6.4: controles de abuso e contadores sem rotulos com dados pessoais.
#[allow(dead_code)] // auth_admin tambem compila auth.rs.
#[path = "auth/security64.rs"]
mod security64;

#[allow(dead_code)] // Servidor HTTP, nao utilitario administrativo.
pub(super) fn security_metrics() -> String {
    security64::metrics()
}
