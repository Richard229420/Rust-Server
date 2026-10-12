use crate::request::Request;
use crate::response::Response;

pub fn home(_req: &Request) -> Response {
    Response::new(200, "<h1>Home</h1><p>Servidor Rust funcionando!</p>")
}

pub fn about(_req: &Request) -> Response {
    Response::new(200, "<h1>About</h1><p>Servidor HTTP escrito em Rust.</p>")
}

pub fn users(_req: &Request) -> Response {
    Response::new(200, "<h1>Users</h1><p>Lista de usuarios.</p>")
}

pub fn not_found(_req: &Request) -> Response {
    Response::new(404, "<h1>404</h1><p>Pagina nao encontrada.</p>")
}
