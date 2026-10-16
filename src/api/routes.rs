//! Despacho REST /api/v1 e validacao basica dos metadados HTTP.

use super::validation::{MAX_JSON_BODY, has_json_content_type};
use super::{Api, ApiResponse};
use std::collections::HashMap;

impl Api {
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
