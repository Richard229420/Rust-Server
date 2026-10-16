//! Testes da API preservados da Fase 5.1.
use super::*;
use std::collections::HashMap;

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
    let api = Api::in_memory();
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
    let api = Api::in_memory();
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
    let api = Api::in_memory();
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
    let api = Api::in_memory();
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
    let api = Api::in_memory();
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
fn sqlite_persists_after_reopening() {
    use std::time::{SystemTime, UNIX_EPOCH};
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("relogio")
        .as_nanos();
    let directory =
        std::env::temp_dir().join(format!("rust-server-sqlite-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("diretorio temporario");
    let path = directory.join("users.sqlite3");
    {
        let api = Api {
            store: Mutex::new(Store::open_file(&path).expect("abrir banco")),
        };
        let created = call(
            &api,
            "POST",
            "/api/v1/users",
            r#"{"name":"Ana","email":"ana@example.com"}"#,
        );
        assert_eq!(created.status, 201);
    }
    {
        let api = Api {
            store: Mutex::new(Store::open_file(&path).expect("reabrir banco")),
        };
        assert_eq!(call(&api, "GET", "/api/v1/users/1", "").status, 200);
        assert_eq!(
            call(
                &api,
                "POST",
                "/api/v1/users",
                r#"{"name":"Duplicada","email":"ANA@EXAMPLE.COM"}"#
            )
            .status,
            409
        );
        assert_eq!(call(&api, "DELETE", "/api/v1/users/1", "").status, 204);
        assert_eq!(
            call(
                &api,
                "POST",
                "/api/v1/users",
                r#"{"name":"Bia","email":"bia@example.com"}"#
            )
            .status,
            201
        );
        assert_eq!(call(&api, "GET", "/api/v1/users/2", "").status, 200);
    }
    std::fs::remove_dir_all(&directory).expect("remover diretorio temporario");
}

#[test]
fn reject_duplicate_content_type_header() {
    let api = Api::in_memory();
    let raw = b"POST /api/v1/users HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n";
    assert_eq!(
        api.handle("POST", "/api/v1/users", &headers(), b"{}", raw)
            .status,
        400
    );
}
