//! Regras do caso de uso: CRUD de usuarios e traducao de erros do repositorio.

use super::models::User;
use super::sqlite_store::StoreError;
use super::validation::{parse_pagination, parse_user_input};
use super::{Api, ApiResponse};
use serde_json::json;

impl Api {
    fn storage_error(error: StoreError) -> ApiResponse {
        match error {
            StoreError::EmailConflict => {
                ApiResponse::error(409, "Conflict", "email_conflict", "Email ja cadastrado")
            }
            StoreError::Capacity => ApiResponse::error(
                503,
                "Service Unavailable",
                "capacity_reached",
                "Limite de usuarios do laboratorio atingido",
            ),
            StoreError::Sql(error) => {
                eprintln!("[ERROR] SQLite: {error}");
                ApiResponse::error(
                    500,
                    "Internal Server Error",
                    "database_error",
                    "Erro ao acessar dados",
                )
            }
        }
    }

    pub(super) fn list(&self, query: Option<&str>) -> ApiResponse {
        let (limit, offset) = match parse_pagination(query) {
            Ok(pagination) => pagination,
            Err(error) => return error,
        };
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match store.list(limit, offset) {
            Ok((users, total)) => ApiResponse::json(
                200,
                "OK",
                json!({
                    "data": users.iter().map(User::to_json).collect::<Vec<_>>(),
                    "pagination": {"total": total, "limit": limit, "offset": offset}
                }),
            ),
            Err(error) => Self::storage_error(error),
        }
    }

    pub(super) fn get(&self, id: u64) -> ApiResponse {
        let store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match store.get(id) {
            Ok(Some(user)) => ApiResponse::json(200, "OK", json!({"data": user.to_json()})),
            Ok(None) => ApiResponse::not_found(),
            Err(error) => Self::storage_error(error),
        }
    }

    pub(super) fn create(&self, body: &[u8]) -> ApiResponse {
        let input = match parse_user_input(body, true) {
            Ok(input) => input,
            Err(error) => return error,
        };
        let name = input.name.unwrap_or_default();
        let email = input.email.unwrap_or_default();
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match store.create(&name, &email) {
            Ok(user) => {
                let id = user.id;
                let mut response =
                    ApiResponse::json(201, "Created", json!({"data": user.to_json()}));
                response
                    .extra_headers
                    .push(("Location", format!("/api/v1/users/{id}")));
                response
            }
            Err(error) => Self::storage_error(error),
        }
    }

    pub(super) fn update(&self, id: u64, body: &[u8], partial: bool) -> ApiResponse {
        let input = match parse_user_input(body, !partial) {
            Ok(input) => input,
            Err(error) => return error,
        };
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match store.update(id, input.name, input.email) {
            Ok(Some(user)) => ApiResponse::json(200, "OK", json!({"data": user.to_json()})),
            Ok(None) => ApiResponse::not_found(),
            Err(error) => Self::storage_error(error),
        }
    }

    pub(super) fn delete(&self, id: u64) -> ApiResponse {
        let mut store = self
            .store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match store.delete(id) {
            Ok(true) => ApiResponse::no_content(),
            Ok(false) => ApiResponse::not_found(),
            Err(error) => Self::storage_error(error),
        }
    }
}
