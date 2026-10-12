//! Fase 5: API REST JSON versionada, sem framework web.
//! Dados apenas em memoria; destinada ao laboratorio local.

use std::collections::{BTreeMap, HashMap};
use std::sync::RwLock;

use serde_json::{Value, json};

const MAX_USERS: usize = 1_000;
const MAX_JSON_BODY: usize = 4_096;
const MAX_PAGE_SIZE: usize = 100;

#[derive(Clone)]
struct User {
    id: u64,
    name: String,
    email: String,
}

impl User {
    fn to_json(&self) -> Value {
        json!({"id": self.id, "name": self.name, "email": self.email})
    }
}

struct State {
    next_id: u64,
    users: BTreeMap<u64, User>,
}

pub struct Api {
    state: RwLock<State>,
}

pub struct ApiResponse {
    pub status: u16,
    pub reason: &'static str,
    pub body: String,
    pub extra_headers: Vec<(&'static str, String)>,
}

impl ApiResponse {
    fn json(status: u16, reason: &'static str, body: Value) -> Self {
        Self {
            status,
            reason,
            body: body.to_string(),
            extra_headers: Vec::new(),
        }
    }

    fn error(status: u16, reason: &'static str, code: &'static str, message: &'static str) -> Self {
        Self::json(
            status,
            reason,
            json!({"error": {"code": code, "message": message}}),
        )
    }

    fn method_not_allowed(allowed: &'static str) -> Self {
        let mut response = Self::error(
            405,
            "Method Not Allowed",
            "method_not_allowed",
            "Metodo HTTP nao permitido nesta rota",
        );
        response.extra_headers.push(("Allow", allowed.to_string()));
        response
    }

    fn not_found() -> Self {
        Self::error(404, "Not Found", "not_found", "Recurso nao encontrado")
    }

    fn bad_request() -> Self {
        Self::error(400, "Bad Request", "bad_request", "Requisicao invalida")
    }

    fn no_content() -> Self {
        Self {
            status: 204,
            reason: "No Content",
            body: String::new(),
            extra_headers: Vec::new(),
        }
    }
}

#[derive(Default)]
struct UserInput {
    name: Option<String>,
    email: Option<String>,
}

impl Api {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(State {
                next_id: 1,
                users: BTreeMap::new(),
            }),
        }
    }

    pub fn handle(
        &self,
        method: &str,
        request_target: &str,
        headers: &HashMap<String, String>,
        body: &[u8],
        raw_head: &[u8],
    ) -> ApiResponse {
        let (path, query) = match request_target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (request_target, None),
        };

        let is_collection = path == "/api/v1/users";
        let maybe_id = path.strip_prefix("/api/v1/users/");
        if !is_collection && maybe_id.is_none() {
            return ApiResponse::not_found();
        }

        let allowed = if is_collection {
            "GET, POST"
        } else {
            "GET, PUT, PATCH, DELETE"
        };
        if !allowed.split(", ").any(|accepted| accepted == method) {
            return ApiResponse::method_not_allowed(allowed);
        }

        if method != "GET" && query.is_some() {
            return ApiResponse::bad_request();
        }
        if method == "GET" && !is_collection && query.is_some() {
            return ApiResponse::bad_request();
        }
        if matches!(method, "GET" | "DELETE") && !body.is_empty() {
            return ApiResponse::bad_request();
        }

        // Verifica a multiplicidade no header bruto: o parser legado usa HashMap
        // e a duplicacao de Content-Type nao deve depender de sua ordem.
        if raw_head
            .split(|&b| b == b'\n')
            .filter_map(|line| line.split_once_byte(b':'))
            .filter(|(key, _)| key.eq_ignore_ascii_case(b"content-type"))
            .count()
            > 1
        {
            return ApiResponse::bad_request();
        }

        if matches!(method, "POST" | "PUT" | "PATCH") {
            if !headers.contains_key("content-length") {
                return ApiResponse::error(
                    411,
                    "Length Required",
                    "length_required",
                    "Envie Content-Length",
                );
            }
            if !has_json_content_type(headers.get("content-type")) {
                return ApiResponse::error(
                    415,
                    "Unsupported Media Type",
                    "unsupported_media_type",
                    "Use Content-Type: application/json",
                );
            }
            if body.len() > MAX_JSON_BODY {
                return ApiResponse::error(
                    413,
                    "Payload Too Large",
                    "payload_too_large",
                    "JSON excede 4096 bytes",
                );
            }
        }

        if is_collection {
            return match method {
                "GET" => self.list(query),
                "POST" => self.create(body),
                _ => ApiResponse::method_not_allowed(allowed),
            };
        }

        let id_text = maybe_id.unwrap_or_default();
        if id_text.is_empty() || !id_text.bytes().all(|b| b.is_ascii_digit()) {
            return ApiResponse::bad_request();
        }
        let id = match id_text.parse::<u64>() {
            Ok(id) if id != 0 => id,
            _ => return ApiResponse::bad_request(),
        };

        match method {
            "GET" => self.get(id),
            "PUT" => self.update(id, body, false),
            "PATCH" => self.update(id, body, true),
            "DELETE" => self.delete(id),
            _ => ApiResponse::method_not_allowed(allowed),
        }
    }

    fn list(&self, query: Option<&str>) -> ApiResponse {
        let (limit, offset) = match parse_pagination(query) {
            Ok(pagination) => pagination,
            Err(error) => return error,
        };
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let users: Vec<Value> = state
            .users
            .values()
            .skip(offset)
            .take(limit)
            .map(User::to_json)
            .collect();
        ApiResponse::json(
            200,
            "OK",
            json!({
                "data": users,
                "pagination": {"total": state.users.len(), "limit": limit, "offset": offset}
            }),
        )
    }

    fn get(&self, id: u64) -> ApiResponse {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match state.users.get(&id) {
            Some(user) => ApiResponse::json(200, "OK", json!({"data": user.to_json()})),
            None => ApiResponse::not_found(),
        }
    }

    fn create(&self, body: &[u8]) -> ApiResponse {
        let input = match parse_user_input(body, true) {
            Ok(input) => input,
            Err(error) => return error,
        };
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.users.len() >= MAX_USERS {
            return ApiResponse::error(
                503,
                "Service Unavailable",
                "capacity_reached",
                "Limite de usuarios do laboratorio atingido",
            );
        }
        let name = input.name.unwrap_or_default();
        let email = input.email.unwrap_or_default();
        if email_in_use(&state.users, &email, None) {
            return ApiResponse::error(409, "Conflict", "email_conflict", "Email ja cadastrado");
        }
        let id = state.next_id;
        state.next_id = match id.checked_add(1) {
            Some(value) => value,
            None => {
                return ApiResponse::error(
                    503,
                    "Service Unavailable",
                    "capacity_reached",
                    "IDs esgotados",
                );
            }
        };
        let user = User { id, name, email };
        let body = json!({"data": user.to_json()});
        state.users.insert(id, user);
        let mut response = ApiResponse::json(201, "Created", body);
        response
            .extra_headers
            .push(("Location", format!("/api/v1/users/{id}")));
        response
    }

    fn update(&self, id: u64, body: &[u8], partial: bool) -> ApiResponse {
        let input = match parse_user_input(body, !partial) {
            Ok(input) => input,
            Err(error) => return error,
        };
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !state.users.contains_key(&id) {
            return ApiResponse::not_found();
        }
        if let Some(ref email) = input.email
            && email_in_use(&state.users, email, Some(id))
        {
            return ApiResponse::error(409, "Conflict", "email_conflict", "Email ja cadastrado");
        }
        let user = state
            .users
            .get_mut(&id)
            .expect("id verificado sob write lock");
        if let Some(name) = input.name {
            user.name = name;
        }
        if let Some(email) = input.email {
            user.email = email;
        }
        ApiResponse::json(200, "OK", json!({"data": user.to_json()}))
    }

    fn delete(&self, id: u64) -> ApiResponse {
        let mut state = self
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.users.remove(&id).is_some() {
            ApiResponse::no_content()
        } else {
            ApiResponse::not_found()
        }
    }
}

// Pequena extensao local para manter parsing de headers sobre bytes, sem UTF-8 permissivo.
trait SplitOnceByte {
    fn split_once_byte(&self, byte: u8) -> Option<(&[u8], &[u8])>;
}

impl SplitOnceByte for [u8] {
    fn split_once_byte(&self, byte: u8) -> Option<(&[u8], &[u8])> {
        let pos = self.iter().position(|&item| item == byte)?;
        Some((&self[..pos], &self[pos + 1..]))
    }
}

fn has_json_content_type(content_type: Option<&String>) -> bool {
    let Some(content_type) = content_type else {
        return false;
    };
    let mut parts = content_type.split(';').map(str::trim);
    if !parts
        .next()
        .unwrap_or_default()
        .eq_ignore_ascii_case("application/json")
    {
        return false;
    }
    parts.all(|part| part.eq_ignore_ascii_case("charset=utf-8"))
}

fn parse_user_input(body: &[u8], require_all: bool) -> Result<UserInput, ApiResponse> {
    if body.is_empty() {
        return Err(ApiResponse::error(
            400,
            "Bad Request",
            "invalid_json",
            "Corpo JSON vazio",
        ));
    }
    let value: Value = serde_json::from_slice(body)
        .map_err(|_| ApiResponse::error(400, "Bad Request", "invalid_json", "JSON malformado"))?;
    let object = value.as_object().ok_or_else(|| {
        ApiResponse::error(
            422,
            "Unprocessable Entity",
            "validation_error",
            "Esperado objeto JSON",
        )
    })?;
    if object.keys().any(|key| key != "name" && key != "email") {
        return Err(ApiResponse::error(
            422,
            "Unprocessable Entity",
            "validation_error",
            "Campos permitidos: name e email",
        ));
    }
    if object.is_empty()
        || (require_all && (!object.contains_key("name") || !object.contains_key("email")))
    {
        return Err(ApiResponse::error(
            422,
            "Unprocessable Entity",
            "validation_error",
            "Informe name e email",
        ));
    }

    let name = if let Some(value) = object.get("name") {
        let name = value.as_str().ok_or_else(validation_error)?;
        let name = name.trim();
        if name.is_empty() || name.chars().count() > 80 || name.chars().any(char::is_control) {
            return Err(validation_error());
        }
        Some(name.to_string())
    } else {
        None
    };

    let email = if let Some(value) = object.get("email") {
        let email = value.as_str().ok_or_else(validation_error)?;
        let email = email.trim().to_ascii_lowercase();
        if !valid_email(&email) {
            return Err(validation_error());
        }
        Some(email)
    } else {
        None
    };

    Ok(UserInput { name, email })
}

fn validation_error() -> ApiResponse {
    ApiResponse::error(
        422,
        "Unprocessable Entity",
        "validation_error",
        "name ou email invalido",
    )
}

fn valid_email(value: &str) -> bool {
    if value.len() > 254 || value.is_empty() || !value.is_ascii() || value.contains("..") {
        return false;
    }
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty()
        || local.len() > 64
        || local.starts_with('.')
        || local.ends_with('.')
        || !local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b'+'))
    {
        return false;
    }
    if !domain.contains('.')
        || domain.starts_with('.')
        || domain.ends_with('.')
        || !domain
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
    {
        return false;
    }
    domain
        .split('.')
        .all(|part| !part.is_empty() && !part.starts_with('-') && !part.ends_with('-'))
}

fn email_in_use(users: &BTreeMap<u64, User>, email: &str, except_id: Option<u64>) -> bool {
    users
        .values()
        .any(|user| Some(user.id) != except_id && user.email == email)
}

fn parse_pagination(query: Option<&str>) -> Result<(usize, usize), ApiResponse> {
    let mut limit = 20;
    let mut offset = 0;
    let mut seen_limit = false;
    let mut seen_offset = false;
    if let Some(query) = query {
        for part in query.split('&') {
            let Some((name, value)) = part.split_once('=') else {
                return Err(ApiResponse::bad_request());
            };
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ApiResponse::bad_request());
            }
            let value: usize = value.parse().map_err(|_| ApiResponse::bad_request())?;
            match name {
                "limit" if !seen_limit && (1..=MAX_PAGE_SIZE).contains(&value) => {
                    limit = value;
                    seen_limit = true;
                }
                "offset" if !seen_offset => {
                    offset = value;
                    seen_offset = true;
                }
                _ => return Err(ApiResponse::bad_request()),
            }
        }
    }
    Ok((limit, offset))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers() -> HashMap<String, String> {
        HashMap::from([
            ("content-type".into(), "application/json".into()),
            ("content-length".into(), "39".into()),
        ])
    }

    fn call(api: &Api, method: &str, path: &str, body: &str) -> ApiResponse {
        api.handle(method, path, &headers(), body.as_bytes(),
            b"POST /api/v1/users HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: 39\r\n\r\n")
    }

    #[test]
    fn create_and_get_user() {
        let api = Api::new();
        let created = call(
            &api,
            "POST",
            "/api/v1/users",
            r#"{"name":"Ana","email":"Ana@Example.com"}"#,
        );
        assert_eq!(created.status, 201);
        assert_eq!(created.extra_headers[0].1, "/api/v1/users/1");
        let found = call(&api, "GET", "/api/v1/users/1", "");
        assert_eq!(found.status, 200);
        assert!(found.body.contains("ana@example.com"));
    }

    #[test]
    fn duplicate_email_rejected_case_insensitive() {
        let api = Api::new();
        assert_eq!(
            call(
                &api,
                "POST",
                "/api/v1/users",
                r#"{"name":"Ana","email":"ANA@example.com"}"#
            )
            .status,
            201
        );
        assert_eq!(
            call(
                &api,
                "POST",
                "/api/v1/users",
                r#"{"name":"Bia","email":"ana@EXAMPLE.com"}"#
            )
            .status,
            409
        );
    }

    #[test]
    fn reject_invalid_json_and_unexpected_fields() {
        let api = Api::new();
        assert_eq!(call(&api, "POST", "/api/v1/users", "{").status, 400);
        assert_eq!(
            call(
                &api,
                "POST",
                "/api/v1/users",
                r#"{"name":"Ana","email":"a@b.com","admin":true}"#
            )
            .status,
            422
        );
    }

    #[test]
    fn put_patch_and_delete() {
        let api = Api::new();
        assert_eq!(
            call(
                &api,
                "POST",
                "/api/v1/users",
                r#"{"name":"Ana","email":"ana@example.com"}"#
            )
            .status,
            201
        );
        assert_eq!(
            call(
                &api,
                "PUT",
                "/api/v1/users/1",
                r#"{"name":"Bia","email":"bia@example.com"}"#
            )
            .status,
            200
        );
        assert_eq!(
            call(&api, "PATCH", "/api/v1/users/1", r#"{"name":"Carla"}"#).status,
            200
        );
        assert_eq!(call(&api, "DELETE", "/api/v1/users/1", "").status, 204);
        assert_eq!(call(&api, "GET", "/api/v1/users/1", "").status, 404);
    }

    #[test]
    fn pagination_and_method_validation() {
        let api = Api::new();
        assert_eq!(
            call(&api, "GET", "/api/v1/users?limit=2&offset=0", "").status,
            200
        );
        assert_eq!(
            call(&api, "GET", "/api/v1/users?limit=1000", "").status,
            400
        );
        assert_eq!(call(&api, "DELETE", "/api/v1/users", "").status, 405);
    }

    #[test]
    fn reject_duplicate_content_type_header() {
        let api = Api::new();
        let raw = b"POST /api/v1/users HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n";
        assert_eq!(
            api.handle("POST", "/api/v1/users", &headers(), b"{}", raw)
                .status,
            400
        );
    }
}
