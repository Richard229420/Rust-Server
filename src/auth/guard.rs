//! Fase 6.3: autorizacao obrigatoria no CRUD de usuarios.
//! A autenticacao e consultada no SQLite em CADA requisicao, sem cache de papeis.
use std::collections::HashMap;

use serde_json::json;

use super::http::{self, AuthResponse};
use super::policy::{Decision, Identity, Operation, Role, authorize};
use super::store;

fn protected_path(target: &str) -> bool {
    let path = target.split('?').next().unwrap_or(target);
    path == "/api/v1/users" || path.starts_with("/api/v1/users/")
}

fn operation(method: &str) -> Option<Operation> {
    match method {
        "GET" => Some(Operation::ReadUsers),
        "POST" => Some(Operation::CreateUsers),
        "PUT" | "PATCH" => Some(Operation::ModifyUsers),
        "DELETE" => Some(Operation::DeleteUsers),
        _ => None, // O roteador REST existente retorna 405 e Allow.
    }
}

fn denied(
    status: u16,
    reason: &'static str,
    code: &'static str,
    message: &'static str,
) -> AuthResponse {
    if status == 401 || status == 403 {
        super::security64::note_denial(&super::database_path(), None, status == 403);
    }
    let mut extra_headers = Vec::new();
    if status == 401 {
        extra_headers.push(("WWW-Authenticate", "Bearer realm=\"rust-server\"".into()));
    }
    AuthResponse {
        status,
        reason,
        body: json!({"error": {"code": code, "message": message}}).to_string(),
        extra_headers,
    }
}

pub(super) fn enforce(
    method: &str,
    target: &str,
    headers: &HashMap<String, String>,
    raw_head: &[u8],
) -> Option<AuthResponse> {
    if !protected_path(target) {
        return None;
    }
    let required = operation(method)?;

    let Some(token) = http::bearer(headers, raw_head) else {
        return Some(denied(
            401,
            "Unauthorized",
            "unauthorized",
            "Token Bearer ausente ou invalido",
        ));
    };
    let principal = match store::authenticate(&super::database_path(), &token) {
        Ok(Some(principal)) => principal,
        Ok(None) => {
            return Some(denied(
                401,
                "Unauthorized",
                "unauthorized",
                "Token Bearer ausente ou invalido",
            ));
        }
        Err(_) => {
            return Some(denied(
                500,
                "Internal Server Error",
                "internal_error",
                "Falha interna de autorizacao",
            ));
        }
    };

    // Fail closed para papel desconhecido e identificador invalido.
    let role = match principal.role.as_str() {
        "viewer" => Role::Viewer,
        "editor" => Role::Editor,
        "admin" => Role::Admin,
        _ => return Some(denied(403, "Forbidden", "forbidden", "Acesso negado")),
    };
    let account_id = match u64::try_from(principal.id) {
        Ok(value) if value > 0 => value,
        _ => return Some(denied(403, "Forbidden", "forbidden", "Acesso negado")),
    };
    let identity = Identity {
        account_id,
        role,
        active: true, // store::authenticate ja exige is_active=1.
    };
    match authorize(Some(&identity), required) {
        Decision::Allow => None,
        Decision::Unauthenticated => Some(denied(
            401,
            "Unauthorized",
            "unauthorized",
            "Token Bearer ausente ou invalido",
        )),
        Decision::Forbidden => Some(denied(403, "Forbidden", "forbidden", "Acesso negado")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn users_targets_only() {
        assert!(protected_path("/api/v1/users"));
        assert!(protected_path("/api/v1/users?limit=5"));
        assert!(protected_path("/api/v1/users/12?foo=bar"));
        assert!(!protected_path("/api/v1/users-other"));
        assert!(!protected_path("/api/v1/auth/login"));
        assert!(!protected_path("/health"));
    }

    #[test]
    fn role_operation_mapping() {
        assert_eq!(operation("GET"), Some(Operation::ReadUsers));
        assert_eq!(operation("POST"), Some(Operation::CreateUsers));
        assert_eq!(operation("PUT"), Some(Operation::ModifyUsers));
        assert_eq!(operation("PATCH"), Some(Operation::ModifyUsers));
        assert_eq!(operation("DELETE"), Some(Operation::DeleteUsers));
        assert_eq!(operation("OPTIONS"), None);
    }

    #[test]
    fn no_token_returns_bearer_challenge() {
        let headers = HashMap::new();
        let response = enforce(
            "GET",
            "/api/v1/users",
            &headers,
            b"GET /api/v1/users HTTP/1.1\r\nHost: localhost\r\n\r\n",
        )
        .unwrap();
        assert_eq!(response.status, 401);
        assert!(
            response
                .extra_headers
                .iter()
                .any(|(name, _)| *name == "WWW-Authenticate")
        );
    }
}
