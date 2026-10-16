//! Entidades e dados de entrada; sem dependencias do protocolo HTTP.

use serde_json::{Value, json};

pub(super) const MAX_USERS: usize = 1_000;

#[derive(Clone)]
pub(super) struct User {
    pub(super) id: u64,
    pub(super) name: String,
    pub(super) email: String,
}

impl User {
    pub(super) fn to_json(&self) -> Value {
        json!({"id": self.id, "name": self.name, "email": self.email})
    }
}

#[derive(Default)]
pub(super) struct UserInput {
    pub(super) name: Option<String>,
    pub(super) email: Option<String>,
}
