use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use crate::config::Config;
use crate::logger;
use crate::request::Request;
use crate::response::Response;
use crate::router::Router;

// Modulo local: nao exige alteracao em main.rs.
#[path = "metrics.rs"]
mod metrics;
use self::metrics::Metrics;

#[path = "security.rs"]
mod security;

#[path = "api.rs"]
mod api;

#[path = "auth.rs"]
mod auth;
use self::api::{Api, ApiResponse};

// Compartilhada pelos workers; estado interno sincronizado por RwLock.
static API: std::sync::OnceLock<Api> = std::sync::OnceLock::new();

const WORKER_COUNT: usize = 16;
const QUEUE_CAPACITY: usize = 128;
const READ_TIMEOUT: Duration = Duration::from_secs(5);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

// Headers fixos de defesa em profundidade (nao enviar HSTS em HTTP).
const SECURITY_HEADERS: &str = "X-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'\r\n";

pub struct Server {
    listener: TcpListener,
    router: Arc<Router>,
    config: Arc<Config>,
}

struct Job {
    stream: TcpStream,
    accepted_at: Instant,
}

// Garante que uma falha em um handler nao deixe o medidor de workers travado.
struct WorkerGuard(Arc<Metrics>);
impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.0.worker_end();
    }
}

impl Server {
    pub fn new(config: Config) -> Self {
        // Falha antecipadamente caso o banco SQLite seja incompativel.
        let _ = API.get_or_init(Api::new);
        auth::initialize()
            .unwrap_or_else(|error| panic!("Falha no banco de autenticacao: {error}"));
        let address = config.address();
        let listener = TcpListener::bind(&address)
            .unwrap_or_else(|error| panic!("Erro ao iniciar servidor em {address}: {error}"));
        let router = Router::new(config.public_dir.clone());
        Self {
            listener,
            router: Arc::new(router),
            config: Arc::new(config),
        }
    }

    pub fn run(&mut self) {
        logger::log_info(&format!(
            "Servidor rodando em http://{} ({} workers, fila {})",
            self.config.address(),
            WORKER_COUNT,
            QUEUE_CAPACITY
        ));

        let metrics = Arc::new(Metrics::new());
        let (sender, receiver) = mpsc::sync_channel::<Job>(QUEUE_CAPACITY);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut _workers = Vec::with_capacity(WORKER_COUNT);

        for id in 0..WORKER_COUNT {
            let receiver = Arc::clone(&receiver);
            let router = Arc::clone(&self.router);
            let config = Arc::clone(&self.config);
            let metrics = Arc::clone(&metrics);

            let worker = thread::Builder::new()
                .name(format!("http-worker-{id:02}"))
                .spawn(move || {
                    loop {
                        // Mutex protege apenas recv(); tratamento acontece fora da trava.
                        let job = match receiver.lock() {
                            Ok(rx) => rx.recv(),
                            Err(poisoned) => poisoned.into_inner().recv(),
                        };
                        let Job {
                            stream,
                            accepted_at,
                        } = match job {
                            Ok(job) => job,
                            Err(_) => break,
                        };
                        metrics.dequeue();
                        metrics.worker_start();
                        let _guard = WorkerGuard(Arc::clone(&metrics));
                        if let Err(error) =
                            Self::handle_connection(&router, &config, &metrics, stream, accepted_at)
                        {
                            logger::log_error(&error);
                        }
                    }
                })
                .unwrap_or_else(|error| panic!("Erro ao criar worker {id}: {error}"));
            _workers.push(worker);
        }

        for incoming in self.listener.incoming() {
            let stream = match incoming {
                Ok(stream) => stream,
                Err(error) => {
                    logger::log_error(&format!("Erro ao aceitar conexao: {error}"));
                    continue;
                }
            };
            metrics.accept();
            let job = Job {
                stream,
                accepted_at: Instant::now(),
            };
            // Incrementa ANTES de enviar, para o worker poder decrementar sem corrida.
            metrics.enqueue();
            match sender.try_send(job) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(mut job)) => {
                    metrics.dequeue();
                    metrics.reject_overload();
                    let _ = job.stream.set_write_timeout(Some(Duration::from_secs(1)));
                    let response = Response::new(503, "<h1>503</h1><p>Service Unavailable</p>");
                    if let Err(error) =
                        Self::send_response(&mut job.stream, &response, &metrics, job.accepted_at)
                    {
                        logger::log_error(&format!("Erro ao enviar HTTP 503: {error}"));
                    }
                }
                Err(mpsc::TrySendError::Disconnected(_job)) => {
                    metrics.dequeue();
                    logger::log_error("Thread pool sem workers; fila encerrada.");
                    break;
                }
            }
        }
    }

    fn send_response(
        stream: &mut TcpStream,
        response: &Response,
        metrics: &Metrics,
        accepted_at: Instant,
    ) -> Result<(), String> {
        // Acrescenta headers defensivos sem alterar Response/router.rs.
        let bytes = response.to_bytes();
        let boundary = bytes
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| "Resposta HTTP sem separador de headers".to_string())?;
        let mut protected = Vec::with_capacity(bytes.len() + SECURITY_HEADERS.len());
        protected.extend_from_slice(&bytes[..boundary + 2]);
        protected.extend_from_slice(SECURITY_HEADERS.as_bytes());
        protected.extend_from_slice(&bytes[boundary + 2..]);
        stream
            .write_all(&protected)
            .map_err(|error| error.to_string())?;
        metrics.respond(response.status, accepted_at.elapsed());
        Ok(())
    }

    // Emite HTTP JSON, preserva headers defensivos e metricas existentes.
    fn send_api_response(
        stream: &mut TcpStream,
        response: &ApiResponse,
        metrics: &Metrics,
        accepted_at: Instant,
    ) -> Result<(), String> {
        let mut headers = format!(
            "HTTP/1.1 {} {}\r\nConnection: close\r\nCache-Control: no-store\r\n{SECURITY_HEADERS}",
            response.status, response.reason
        );
        for (name, value) in &response.extra_headers {
            headers.push_str(&format!("{name}: {value}\r\n"));
        }
        // RFC 9110: a resposta 204 nao contem body ou Content-Length.
        if response.status != 204 {
            headers.push_str("Content-Type: application/json; charset=utf-8\r\n");
            headers.push_str(&format!("Content-Length: {}\r\n", response.body.len()));
        }
        headers.push_str("\r\n");
        stream
            .write_all(headers.as_bytes())
            .map_err(|error| error.to_string())?;
        if response.status != 204 {
            stream
                .write_all(response.body.as_bytes())
                .map_err(|error| error.to_string())?;
        }
        metrics.respond(response.status, accepted_at.elapsed());
        Ok(())
    }

    fn send_plaintext(
        stream: &mut TcpStream,
        status: u16,
        reason: &str,
        body: &str,
        content_type: &str,
        metrics: &Metrics,
        accepted_at: Instant,
    ) -> Result<(), String> {
        let head = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n{SECURITY_HEADERS}\r\n",
            body.len()
        );
        stream
            .write_all(head.as_bytes())
            .map_err(|error| error.to_string())?;
        stream
            .write_all(body.as_bytes())
            .map_err(|error| error.to_string())?;
        metrics.respond(status, accepted_at.elapsed());
        Ok(())
    }

    fn send_request_timeout(
        stream: &mut TcpStream,
        metrics: &Metrics,
        accepted_at: Instant,
        total: bool,
    ) -> Result<(), String> {
        metrics.timeout(total);
        let response = Response::new(408, "<h1>408</h1><p>Request Timeout</p>");
        Self::send_response(stream, &response, metrics, accepted_at)
    }

    fn read_with_timeout(
        stream: &mut TcpStream,
        chunk: &mut [u8],
        deadline: Instant,
        metrics: &Metrics,
        accepted_at: Instant,
    ) -> Result<usize, String> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Self::send_request_timeout(stream, metrics, accepted_at, true)?;
            return Err("Tempo total de recebimento HTTP excedido.".to_string());
        }
        stream
            .set_read_timeout(Some(remaining.min(READ_TIMEOUT)))
            .map_err(|error| format!("Erro ao configurar timeout TCP: {error}"))?;
        match stream.read(chunk) {
            Ok(bytes_read) => {
                if Instant::now() >= deadline {
                    Self::send_request_timeout(stream, metrics, accepted_at, true)?;
                    Err("Tempo total de recebimento HTTP excedido.".to_string())
                } else {
                    Ok(bytes_read)
                }
            }
            Err(error) if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                let total = Instant::now() >= deadline;
                Self::send_request_timeout(stream, metrics, accepted_at, total)?;
                if total {
                    Err("Tempo total de recebimento HTTP excedido.".to_string())
                } else {
                    Err("Tempo limite de leitura TCP excedido.".to_string())
                }
            }
            Err(error) => Err(format!("Erro de leitura TCP: {error}")),
        }
    }

    fn handle_connection(
        router: &Router,
        config: &Config,
        metrics: &Metrics,
        mut stream: TcpStream,
        accepted_at: Instant,
    ) -> Result<(), String> {
        let deadline = accepted_at + REQUEST_TIMEOUT;
        stream
            .set_write_timeout(Some(WRITE_TIMEOUT))
            .map_err(|error| format!("Erro ao configurar timeout de escrita: {error}"))?;
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 1024];

        // Espera por \r\n\r\n (inclusive em leituras fragmentadas).
        loop {
            let received =
                Self::read_with_timeout(&mut stream, &mut chunk, deadline, metrics, accepted_at)?;
            if received == 0 {
                if buffer.is_empty() {
                    return Ok(());
                }
                let response = Response::new(400, "<h1>400</h1><p>Bad Request</p>");
                Self::send_response(&mut stream, &response, metrics, accepted_at)?;
                return Err("Headers HTTP incompletos.".to_string());
            }
            buffer.extend_from_slice(&chunk[..received]);
            if buffer.len() > config.max_request_size {
                let response = Response::new(413, "<h1>413</h1><p>Payload Too Large</p>");
                Self::send_response(&mut stream, &response, metrics, accepted_at)?;
                return Err("Requisicao excede o limite permitido.".to_string());
            }
            if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }

        let header_end = buffer
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|pos| pos + 4)
            .ok_or_else(|| "Final dos headers nao encontrado".to_string())?;

        // Verificacao estrita sobre os bytes originais, antes do parser legado.
        // Evita interpretacoes divergentes entre o proxy HTTP e o backend.
        if let Err(error) = security::validate_request_head(&buffer[..header_end]) {
            let response = Response::new(400, "<h1>400</h1><p>Bad Request</p>");
            Self::send_response(&mut stream, &response, metrics, accepted_at)?;
            return Err(format!("Cabecalho HTTP rejeitado: {error}"));
        }

        let mut request = match Request::parse(&buffer[..header_end]) {
            Ok(request) => request,
            Err(error) => {
                let response = Response::new(400, "<h1>400</h1><p>Bad Request</p>");
                Self::send_response(&mut stream, &response, metrics, accepted_at)?;
                return Err(error);
            }
        };

        // Erros de Content-Length devem gerar uma resposta HTTP (nao apenas EOF).
        let content_length = match Request::content_length(&request.headers) {
            Ok(length) => length,
            Err(error) => {
                let response = Response::new(400, "<h1>400</h1><p>Bad Request</p>");
                Self::send_response(&mut stream, &response, metrics, accepted_at)?;
                return Err(format!("Content-Length rejeitado: {error}"));
            }
        };
        let total_size = match header_end.checked_add(content_length) {
            Some(size) if size <= config.max_request_size => size,
            _ => {
                let response = Response::new(413, "<h1>413</h1><p>Payload Too Large</p>");
                Self::send_response(&mut stream, &response, metrics, accepted_at)?;
                return Err("Body excede o limite permitido.".to_string());
            }
        };
        // Somente uma requisicao por conexao: bytes excedentes nao sao
        // interpretados como uma segunda mensagem/pipeline.
        if buffer.len() > total_size {
            let response = Response::new(400, "<h1>400</h1><p>Bad Request</p>");
            Self::send_response(&mut stream, &response, metrics, accepted_at)?;
            return Err("Bytes extras apos o corpo HTTP (pipelining nao suportado)".to_string());
        }
        while buffer.len() < total_size {
            let remaining = total_size - buffer.len();
            let size = remaining.min(chunk.len());
            let received = Self::read_with_timeout(
                &mut stream,
                &mut chunk[..size],
                deadline,
                metrics,
                accepted_at,
            )?;
            if received == 0 {
                let response = Response::new(400, "<h1>400</h1><p>Bad Request</p>");
                Self::send_response(&mut stream, &response, metrics, accepted_at)?;
                return Err("Body HTTP incompleto.".to_string());
            }
            buffer.extend_from_slice(&chunk[..received]);
        }
        request.body = buffer[header_end..total_size].to_vec();
        if !request.body.is_empty() {
            logger::log_info(&format!("Body recebido: {} bytes", request.body.len()));
        }

        if Instant::now() >= deadline {
            Self::send_request_timeout(&mut stream, metrics, accepted_at, true)?;
            return Err("Tempo total de recebimento HTTP excedido.".to_string());
        }

        // Rotas de observabilidade: nao alteram router.rs.
        // /metrics e restrito a clientes locais para evitar exposicao acidental.
        if request.path == "/health" || request.path == "/metrics" {
            let status = if request.method != "GET" {
                let response = Response::new(405, "<h1>405</h1><p>Method Not Allowed</p>");
                Self::send_response(&mut stream, &response, metrics, accepted_at)?;
                405
            } else if request.path == "/health" {
                Self::send_plaintext(
                    &mut stream,
                    200,
                    "OK",
                    "ok\n",
                    "text/plain; charset=utf-8",
                    metrics,
                    accepted_at,
                )?;
                200
            } else if stream
                .peer_addr()
                .map(|a| a.ip().is_loopback())
                .unwrap_or(false)
            {
                let body = metrics.render();
                Self::send_plaintext(
                    &mut stream,
                    200,
                    "OK",
                    &body,
                    "text/plain; version=0.0.4; charset=utf-8",
                    metrics,
                    accepted_at,
                )?;
                200
            } else {
                let response = Response::new(403, "<h1>403</h1><p>Forbidden</p>");
                Self::send_response(&mut stream, &response, metrics, accepted_at)?;
                403
            };
            logger::log_request(
                &request.method,
                &request.path,
                status,
                accepted_at.elapsed(),
            );
            return Ok(());
        }

        // Fase 5: API JSON depois da validacao HTTP e antes das rotas HTML.
        // Fase 6.2: identidade e sessoes antes do CRUD REST; RBAC sera aplicado na 6.3.
        if let Some(auth_response) = auth::handle_http(
            &request.method,
            &request.path,
            &request.headers,
            &request.body,
            &buffer[..header_end],
        ) {
            let response = ApiResponse {
                status: auth_response.status,
                reason: auth_response.reason,
                body: auth_response.body,
                extra_headers: auth_response.extra_headers,
            };
            let status = response.status;
            Self::send_api_response(&mut stream, &response, metrics, accepted_at)?;
            logger::log_request(
                &request.method,
                &request.path,
                status,
                accepted_at.elapsed(),
            );
            return Ok(());
        }

        // Fase 6.3: politica RBAC obrigatoria antes do CRUD REST.
        if let Some(guard_response) = auth::guard_users(
            &request.method,
            &request.path,
            &request.headers,
            &buffer[..header_end],
        ) {
            let response = ApiResponse {
                status: guard_response.status,
                reason: guard_response.reason,
                body: guard_response.body,
                extra_headers: guard_response.extra_headers,
            };
            let status = response.status;
            Self::send_api_response(&mut stream, &response, metrics, accepted_at)?;
            logger::log_request(
                &request.method,
                &request.path,
                status,
                accepted_at.elapsed(),
            );
            return Ok(());
        }

        if request.path == "/api" || request.path.starts_with("/api/") {
            let api = API.get_or_init(Api::new);
            let response = api.handle(
                &request.method,
                &request.path,
                &request.headers,
                &request.body,
                &buffer[..header_end],
            );
            let status = response.status;
            Self::send_api_response(&mut stream, &response, metrics, accepted_at)?;
            logger::log_request(
                &request.method,
                &request.path,
                status,
                accepted_at.elapsed(),
            );
            return Ok(());
        }

        let response = router.route(&request);
        let status = response.status;
        Self::send_response(&mut stream, &response, metrics, accepted_at)?;
        logger::log_request(
            &request.method,
            &request.path,
            status,
            accepted_at.elapsed(),
        );
        Ok(())
    }
}
