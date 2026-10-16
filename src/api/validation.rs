//! Validacao de payloads JSON, Content-Type e paginacao.

use super::models::UserInput;
use super::response::ApiResponse;
use serde_json::Value;

pub(super) const MAX_JSON_BODY: usize = 4_096;
const MAX_PAGE_SIZE: usize = 100;

pub(super) fn has_json_content_type(content_type: Option<&String>) -> bool {
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

pub(super) fn parse_user_input(body: &[u8], require_all: bool) -> Result<UserInput, ApiResponse> {
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

pub(super) fn parse_pagination(query: Option<&str>) -> Result<(usize, usize), ApiResponse> {
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
