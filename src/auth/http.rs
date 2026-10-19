//! Endpoints 6.2 isolados. Nao instala RBAC no CRUD de /api/v1/users (Fase 6.3).
use std::collections::HashMap;

use serde_json::{Value, json};

use super::store;
#[derive(Debug)]
pub(crate) struct AuthResponse {
    pub(crate) status: u16,
    pub(crate) reason: &'static str,
    pub(crate) body: String,
    pub(crate) extra_headers: Vec<(&'static str, String)>,
}

const MAX_LOGIN_BODY: usize = 4096;

fn response(status: u16, reason: &'static str, body: Value) -> AuthResponse {
    AuthResponse {
        status,
        reason,
        body: body.to_string(),
        extra_headers: Vec::new(),
    }
}

fn error(
    status: u16,
    reason: &'static str,
    code: &'static str,
    message: &'static str,
) -> AuthResponse {
    response(
        status,
        reason,
        json!({"error": {"code": code, "message": message}}),
    )
}

fn unauthorized() -> AuthResponse {
    let mut resp = error(
        401,
        "Unauthorized",
        "unauthorized",
        "Credenciais ausentes ou invalidas",
    );
    resp.extra_headers
        .push(("WWW-Authenticate", "Bearer realm=\"rust-server\"".into()));
    resp
}

fn bad_request() -> AuthResponse {
    error(400, "Bad Request", "bad_request", "Requisicao invalida")
}

fn method_not_allowed(methods: &'static str) -> AuthResponse {
    let mut resp = error(
        405,
        "Method Not Allowed",
        "method_not_allowed",
        "Metodo nao permitido",
    );
    resp.extra_headers.push(("Allow", methods.into()));
    resp
}

fn headers_count(raw_head: &[u8], target: &[u8]) -> usize {
    raw_head
        .split(|byte| *byte == b'\n')
        .filter_map(|line| line.split_once_byte(b':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case(target))
        .count()
}

trait SplitOnceByte {
    fn split_once_byte(&self, needle: u8) -> Option<(&[u8], &[u8])>;
}
impl SplitOnceByte for [u8] {
    fn split_once_byte(&self, needle: u8) -> Option<(&[u8], &[u8])> {
        let pos = self.iter().position(|byte| *byte == needle)?;
        Some((&self[..pos], &self[pos + 1..]))
    }
}

pub(super) fn bearer(headers: &HashMap<String, String>, raw_head: &[u8]) -> Option<String> {
    if headers_count(raw_head, b"authorization") != 1 {
        return None;
    }
    let auth = headers.get("authorization")?;
    let (scheme, secret) = auth.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("Bearer") && super::credentials::valid_token_format(secret) {
        Some(secret.to_owned())
    } else {
        None
    }
}

fn unexpected_headers(raw_head: &[u8]) -> bool {
    headers_count(raw_head, b"content-type") > 1 || headers_count(raw_head, b"authorization") > 1
}

pub(super) fn handle(
    method: &str,
    target: &str,
    headers: &HashMap<String, String>,
    body: &[u8],
    raw_head: &[u8],
    peer_ip: &str,
) -> Option<AuthResponse> {
    let path = target.split('?').next().unwrap_or(target);
    if path != "/api/v1/auth" && !path.starts_with("/api/v1/auth/") {
        return None;
    }
    if target != path || unexpected_headers(raw_head) {
        return Some(bad_request());
    }
    let expected = match path {
        "/api/v1/auth/login" | "/api/v1/auth/logout" => "POST",
        "/api/v1/auth/me" => "GET",
        _ => {
            return Some(error(
                404,
                "Not Found",
                "not_found",
                "Recurso nao encontrado",
            ));
        }
    };
    if method != expected {
        return Some(method_not_allowed(expected));
    }
    match path {
        "/api/v1/auth/login" => Some(login(headers, body, peer_ip)),
        "/api/v1/auth/me" => Some(me(headers, raw_head, body)),
        "/api/v1/auth/logout" => Some(logout(headers, raw_head, body)),
        _ => unreachable!(),
    }
}

fn login(headers: &HashMap<String, String>, body: &[u8], peer_ip: &str) -> AuthResponse {
    if !headers.contains_key("content-length") {
        return error(
            411,
            "Length Required",
            "length_required",
            "Envie Content-Length",
        );
    }
    if !headers.get("content-type").is_some_and(|value| {
        value.eq_ignore_ascii_case("application/json")
            || value.eq_ignore_ascii_case("application/json; charset=utf-8")
    }) {
        return error(
            415,
            "Unsupported Media Type",
            "unsupported_media_type",
            "Use application/json",
        );
    }
    if body.is_empty() || body.len() > MAX_LOGIN_BODY {
        return bad_request();
    }
    let Ok(value) = serde_json::from_slice::<Value>(body) else {
        return bad_request();
    };
    let Some(object) = value.as_object() else {
        return bad_request();
    };
    if object.len() != 2 || !object.contains_key("username") || !object.contains_key("password") {
        return bad_request();
    }
    let (Some(username), Some(password)) = (
        object.get("username").and_then(Value::as_str),
        object.get("password").and_then(Value::as_str),
    ) else {
        return bad_request();
    };
    if !super::credentials::username_valid(username)
        || password.is_empty()
        || password.len() > super::credentials::PASSWORD_MAX
    {
        return unauthorized();
    }
    // Antes de executar Argon2id: limite por conta e IP TCP e no maximo 2 hashes simultaneos.
    let admission = match super::security64::admit(username, peer_ip) {
        Ok(value) => value,
        Err(reason) => {
            let (retry, event) = match reason {
                super::security64::AdmissionError::RateLimited => (60, "login_limited"),
                super::security64::AdmissionError::Busy => (1, "login_overload"),
            };
            let _ = super::security64::audit(&super::database_path(), None, event, "denied");
            let mut response = error(
                429,
                "Too Many Requests",
                "rate_limited",
                "Tente novamente mais tarde",
            );
            response
                .extra_headers
                .push(("Retry-After", retry.to_string()));
            return response;
        }
    };
    let result = store::login(&super::database_path(), username, password);
    if let Ok(ref value) = result {
        super::security64::finish(&admission, value.is_some());
    }
    drop(admission); // libera vaga Argon2 mesmo em erro SQLite
    match result {
        Ok(Some(session)) => response(
            200,
            "OK",
            json!({
                "access_token": session.token,
                "token_type": "Bearer",
                "expires_in": store::SESSION_TTL_SECS,
                "expires_at": session.principal.expires_at,
            }),
        ),
        Ok(None) => unauthorized(),
        Err(_) => error(
            500,
            "Internal Server Error",
            "internal_error",
            "Falha interna de autenticacao",
        ),
    }
}

fn me(headers: &HashMap<String, String>, raw_head: &[u8], body: &[u8]) -> AuthResponse {
    if !body.is_empty() {
        return bad_request();
    }
    let Some(secret) = bearer(headers, raw_head) else {
        return unauthorized();
    };
    match store::authenticate(&super::database_path(), &secret) {
        Ok(Some(principal)) => response(
            200,
            "OK",
            json!({"id": principal.id, "username": principal.username, "role": principal.role, "expires_at": principal.expires_at}),
        ),
        Ok(None) => unauthorized(),
        Err(_) => error(
            500,
            "Internal Server Error",
            "internal_error",
            "Falha interna de autenticacao",
        ),
    }
}

fn logout(headers: &HashMap<String, String>, raw_head: &[u8], body: &[u8]) -> AuthResponse {
    if !body.is_empty() {
        return bad_request();
    }
    let Some(secret) = bearer(headers, raw_head) else {
        return unauthorized();
    };
    match store::revoke(&super::database_path(), &secret) {
        Ok(true) => AuthResponse {
            status: 204,
            reason: "No Content",
            body: String::new(),
            extra_headers: Vec::new(),
        },
        Ok(false) => unauthorized(),
        Err(_) => error(
            500,
            "Internal Server Error",
            "internal_error",
            "Falha interna de autenticacao",
        ),
    }
}
