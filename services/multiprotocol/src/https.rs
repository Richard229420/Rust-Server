//! Gateway HTTPS em Rust, com TLS 1.2/1.3 via rustls.
//! Encaminha uma requisicao HTTP/1.x por conexao ao backend Rust-Server local.
//! Nao suporta Upgrade, chunked REQUESTS, pipelining ou HTTP/2.

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::error::Error;
use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 64;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(10);

type GatewayError = (&'static str, &'static str);

pub fn load_tls(
    cert: &Path,
    key: &Path,
) -> Result<Arc<ServerConfig>, Box<dyn Error + Send + Sync>> {
    let certificates: Vec<_> =
        rustls_pemfile::certs(&mut BufReader::new(File::open(cert)?)).collect::<Result<_, _>>()?;
    if certificates.is_empty() {
        return Err("Certificado TLS vazio".into());
    }
    let private_key = rustls_pemfile::private_key(&mut BufReader::new(File::open(key)?))?
        .ok_or("Chave privada TLS ausente")?;
    let mut server =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certificates, private_key)?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(server))
}

struct ConnectionGuard(Arc<AtomicUsize>);
impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub fn serve(addr: SocketAddr, upstream: SocketAddr, tls: Arc<ServerConfig>) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let active = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        let socket = match incoming {
            Ok(value) => value,
            Err(err) => {
                eprintln!("[HTTPS] erro ao aceitar: {err}");
                continue;
            }
        };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            drop(socket);
            continue;
        }
        let active_worker = Arc::clone(&active);
        let tls_worker = Arc::clone(&tls);
        let spawned = thread::Builder::new()
            .name("https-worker".into())
            .spawn(move || {
                let _guard = ConnectionGuard(active_worker);
                if let Err(err) = handle(socket, upstream, tls_worker) {
                    eprintln!("[HTTPS] conexao encerrada: {err}");
                }
            });
        if let Err(err) = spawned {
            active.fetch_sub(1, Ordering::SeqCst);
            return Err(err);
        }
    }
    Ok(())
}

fn handle(socket: TcpStream, upstream: SocketAddr, tls: Arc<ServerConfig>) -> io::Result<()> {
    socket.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    socket.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    let connection = ServerConnection::new(tls).map_err(io::Error::other)?;
    let mut secure = StreamOwned::new(connection, socket);
    let request = match read_request(&mut secure) {
        Ok(value) => value,
        Err((status, body)) => {
            return reply(&mut secure, status, body);
        }
    };

    let mut backend = match TcpStream::connect_timeout(&upstream, SOCKET_TIMEOUT) {
        Ok(conn) => conn,
        Err(_) => return reply(&mut secure, "502 Bad Gateway", "Backend indisponivel"),
    };
    backend.set_read_timeout(Some(SOCKET_TIMEOUT))?;
    backend.set_write_timeout(Some(SOCKET_TIMEOUT))?;
    if backend.write_all(&request).is_err() {
        return reply(
            &mut secure,
            "502 Bad Gateway",
            "Falha ao encaminhar requisicao",
        );
    }
    // Backend da Fase 6.4 encerra a conexao apos enviar a resposta.
    io::copy(&mut backend, &mut secure)?;
    secure.flush()
}

fn reply(stream: &mut impl Write, status: &str, body: &str) -> io::Result<()> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn read_request(stream: &mut impl Read) -> Result<Vec<u8>, GatewayError> {
    let mut received = Vec::with_capacity(2048);
    let mut chunk = [0_u8; 2048];
    let header_end = loop {
        if let Some(n) = received.windows(4).position(|w| w == b"\r\n\r\n") {
            break n + 4;
        }
        if received.len() >= MAX_HEADERS {
            return Err(("431 Request Header Fields Too Large", "Cabecalhos grandes"));
        }
        let n = stream
            .read(&mut chunk)
            .map_err(|_| ("408 Request Timeout", "Leitura HTTP incompleta"))?;
        if n == 0 {
            return Err(("400 Bad Request", "Requisicao incompleta"));
        }
        received.extend_from_slice(&chunk[..n]);
        if received.len() > MAX_HEADERS + chunk.len() {
            return Err(("431 Request Header Fields Too Large", "Cabecalhos grandes"));
        }
    };
    if header_end > MAX_HEADERS {
        return Err(("431 Request Header Fields Too Large", "Cabecalhos grandes"));
    }
    let (headers, length) = validate_headers(&received[..header_end])?;
    let wanted = header_end + length;
    if received.len() > wanted {
        return Err(("400 Bad Request", "Pipelining nao suportado"));
    }
    while received.len() < wanted {
        let n = stream
            .read(&mut chunk)
            .map_err(|_| ("408 Request Timeout", "Corpo HTTP incompleto"))?;
        if n == 0 {
            return Err(("400 Bad Request", "Corpo incompleto"));
        }
        if received.len() + n > wanted {
            return Err(("400 Bad Request", "Bytes excedentes apos corpo"));
        }
        received.extend_from_slice(&chunk[..n]);
    }
    let mut result = headers;
    result.extend_from_slice(&received[header_end..]);
    Ok(result)
}

fn validate_headers(raw: &[u8]) -> Result<(Vec<u8>, usize), GatewayError> {
    let text =
        std::str::from_utf8(raw).map_err(|_| ("400 Bad Request", "Cabecalho UTF-8 invalido"))?;
    if !text.ends_with("\r\n\r\n") {
        return Err(("400 Bad Request", "Cabecalho sem CRLF"));
    }
    // Rejeita line endings ambiguos e bytes de controle nos headers.
    if raw.iter().enumerate().any(|(i, b)| {
        (*b == b'\n' && (i == 0 || raw[i - 1] != b'\r'))
            || (*b == b'\r' && (i + 1 >= raw.len() || raw[i + 1] != b'\n'))
            || (*b < 0x20 && !matches!(*b, b'\r' | b'\n' | b'\t'))
            || *b == 0x7f
    }) {
        return Err(("400 Bad Request", "Cabecalho malformado"));
    }

    let mut lines = text.split("\r\n");
    let first = lines
        .next()
        .ok_or(("400 Bad Request", "Linha HTTP ausente"))?;
    let words: Vec<_> = first.split(' ').collect();
    if words.len() != 3 {
        return Err(("400 Bad Request", "Linha HTTP invalida"));
    }
    let (method, target, version) = (words[0], words[1], words[2]);
    if method.is_empty() || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(("400 Bad Request", "Metodo HTTP invalido"));
    }
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(("505 HTTP Version Not Supported", "Apenas HTTP/1.x"));
    }
    if !target.starts_with('/') || target.contains('#') || target.chars().any(char::is_control) {
        return Err(("400 Bad Request", "Caminho invalido"));
    }
    let path = target.split('?').next().unwrap_or(target);
    if path.contains('%') || path.contains('\\') || path.contains("..") || path.contains("//") {
        return Err(("400 Bad Request", "Caminho ambíguo"));
    }
    // Como o proxy recebe conexoes como 127.0.0.1 no backend, nao deixa
    // endpoints administrativos passarem como se fossem solicitacoes locais.
    if path == "/metrics" || path == "/internal" || path.starts_with("/internal/") {
        return Err(("403 Forbidden", "Endpoint interno indisponivel por HTTPS"));
    }
    let mut host_count = 0;
    let mut content_len = None;
    let mut out = format!("{first}\r\n").into_bytes();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(("400 Bad Request", "obs-fold invalido"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(("400 Bad Request", "Header sem dois pontos"))?;
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
            return Err(("400 Bad Request", "Nome de header invalido"));
        }
        if value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0x7f) {
            return Err(("400 Bad Request", "Valor de header invalido"));
        }
        if name.eq_ignore_ascii_case("host") {
            host_count += 1;
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_len.is_some() {
                return Err(("400 Bad Request", "Content-Length duplicado"));
            }
            let v = value.trim();
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(("400 Bad Request", "Content-Length invalido"));
            }
            content_len = Some(
                v.parse::<usize>()
                    .map_err(|_| ("413 Content Too Large", "Corpo grande"))?,
            );
        }
        if ["transfer-encoding", "upgrade", "expect", "trailer"]
            .iter()
            .any(|item| name.eq_ignore_ascii_case(item))
        {
            return Err(("501 Not Implemented", "Este recurso HTTP nao e suportado"));
        }
        if ["connection", "proxy-connection", "keep-alive", "te"]
            .iter()
            .any(|item| name.eq_ignore_ascii_case(item))
        {
            continue;
        }
        out.extend_from_slice(line.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if version == "HTTP/1.1" && host_count != 1 {
        return Err(("400 Bad Request", "HTTP/1.1 exige Host unico"));
    }
    let length = content_len.unwrap_or(0);
    if length > MAX_BODY {
        return Err(("413 Content Too Large", "Corpo grande"));
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok((out, length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filtra_endpoints_internos() {
        for uri in ["/metrics", "/metrics?x=1", "/internal/security-metrics"] {
            let req = format!("GET {uri} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert_eq!(
                validate_headers(req.as_bytes()).unwrap_err().0,
                "403 Forbidden"
            );
        }
    }

    #[test]
    fn impede_request_smuggling() {
        let duplicate = b"POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n";
        assert!(validate_headers(duplicate).is_err());
        let chunked =
            b"POST /api HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(validate_headers(chunked).is_err());
    }

    #[test]
    fn reconstrucao_remove_connection() {
        let req = b"GET /api/v1/items HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nAuthorization: Bearer abc\r\n\r\n";
        let (headers, body) = validate_headers(req).unwrap();
        let result = String::from_utf8(headers).unwrap();
        assert_eq!(body, 0);
        assert!(result.contains("Connection: close\r\n"));
        assert!(!result.contains("Connection: keep-alive"));
        assert!(result.contains("Authorization: Bearer abc"));
    }

    #[test]
    fn respeita_content_length() {
        let request = b"POST /api HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest";
        let mut cursor = std::io::Cursor::new(request);
        assert!(read_request(&mut cursor).unwrap().ends_with(b"test"));
    }
}
