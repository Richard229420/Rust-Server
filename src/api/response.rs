//! Respostas HTTP e codigos de erro JSON da API.

use serde_json::{Value, json};

pub struct ApiResponse {
    pub status: u16,
    pub reason: &'static str,
    pub body: String,
    pub extra_headers: Vec<(&'static str, String)>,
}

impl ApiResponse {
    pub(super) fn json(status: u16, reason: &'static str, body: Value) -> Self {
        Self {
            status,
            reason,
            body: body.to_string(),
            extra_headers: Vec::new(),
        }
    }

    pub(super) fn error(
        status: u16,
        reason: &'static str,
        code: &'static str,
        message: &'static str,
    ) -> Self {
        Self::json(
            status,
            reason,
            json!({"error": {"code": code, "message": message}}),
        )
    }

    pub(super) fn method_not_allowed(allowed: &'static str) -> Self {
        let mut response = Self::error(
            405,
            "Method Not Allowed",
            "method_not_allowed",
            "Metodo HTTP nao permitido nesta rota",
        );
        response.extra_headers.push(("Allow", allowed.to_string()));
        response
    }

    pub(super) fn not_found() -> Self {
        Self::error(404, "Not Found", "not_found", "Recurso nao encontrado")
    }

    pub(super) fn bad_request() -> Self {
        Self::error(400, "Bad Request", "bad_request", "Requisicao invalida")
    }

    pub(super) fn no_content() -> Self {
        Self {
            status: 204,
            reason: "No Content",
            body: String::new(),
            extra_headers: Vec::new(),
        }
    }
}
