//! Fase 5.2: fachada publica da API REST (sem alterar contrato HTTP/JSON).
//! Separacao: roteamento, validacao, modelo, servico e repositorio SQLite.

use std::path::Path;
use std::sync::Mutex;

#[path = "api/models.rs"]
mod models;
#[path = "api/response.rs"]
mod response;
#[path = "api/routes.rs"]
mod routes;
#[path = "api/service.rs"]
mod service;
#[path = "api/sqlite_store.rs"]
mod sqlite_store;
#[path = "api/validation.rs"]
mod validation;

pub use self::response::ApiResponse;
use self::sqlite_store::Store;

pub struct Api {
    store: Mutex<Store>,
}

impl Api {
    // Falha na abertura do DB deve impedir o boot, nao gerar fallback silencioso.
    pub fn new() -> Self {
        let path = std::env::var("RUST_SERVER_DB_PATH")
            .unwrap_or_else(|_| "data/users.sqlite3".to_owned());
        let store = Store::open_file(Path::new(&path))
            .unwrap_or_else(|error| panic!("Nao foi possivel abrir SQLite em {path}: {error}"));
        Self {
            store: Mutex::new(store),
        }
    }

    #[cfg(test)]
    fn in_memory() -> Self {
        Self {
            store: Mutex::new(Store::in_memory()),
        }
    }
}

#[cfg(test)]
#[path = "api/tests.rs"]
mod tests;
