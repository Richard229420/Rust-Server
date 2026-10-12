use crate::handlers;
use crate::mime;
use crate::request::Request;
use crate::response::Response;
use crate::utils;

pub struct Router {
    public_dir: String,
}

impl Router {
    pub fn new(public_dir: String) -> Self {
        Self { public_dir }
    }

    pub fn route(&self, req: &Request) -> Response {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") => handlers::home(req),

            ("GET", "/about") => handlers::about(req),

            ("GET", "/users") => handlers::users(req),

            ("GET", _) => self.serve_static_file(req),

            _ => Response::new(405, "<h1>405</h1><p>Metodo nao permitido.</p>"),
        }
    }

    fn serve_static_file(&self, req: &Request) -> Response {
        let Some(path) = utils::build_public_path(&self.public_dir, &req.path) else {
            return handlers::not_found(req);
        };

        if !path.is_file() {
            return handlers::not_found(req);
        }

        match utils::read_file(&path) {
            Ok(content) => {
                let content_type = mime::get_mime_type(&path);

                Response::with_content_type(200, content_type, content)
            }

            Err(_) => Response::new(500, "<h1>500</h1><p>Erro interno.</p>"),
        }
    }
}
