//! Camada conservadora de validacao de HTTP/1.1 para o servidor educacional.
//! Opera sobre bytes originais para nao aceitar ambiguidades de framing.
//! Nao substitui um parser HTTP/1.1 completo nem um WAF.

fn is_tchar(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn parse_host(raw: &[u8]) -> Result<(), &'static str> {
    if raw.is_empty() || raw.len() > 253 {
        return Err("Host ausente ou demasiado longo");
    }
    if raw
        .iter()
        .any(|&b| !b.is_ascii_graphic() || matches!(b, b'/' | b'\\' | b'@' | b'?' | b'#'))
    {
        return Err("Host contem caractere proibido");
    }
    let host = std::str::from_utf8(raw).map_err(|_| "Host nao ASCII")?;
    if host.starts_with('[') {
        // Aceita IPv6 com colchetes, opcionalmente seguido de :porta.
        let end = host.find(']').ok_or("Host IPv6 sem fechamento")?;
        let address = &host[1..end];
        address
            .parse::<std::net::Ipv6Addr>()
            .map_err(|_| "IPv6 invalido")?;
        let suffix = &host[end + 1..];
        if !suffix.is_empty() {
            let port = suffix.strip_prefix(':').ok_or("Sufixo Host invalido")?;
            validate_port(port)?;
        }
    } else {
        let (name, port) = match host.rsplit_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        };
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
            || name.starts_with('-')
            || name.ends_with('-')
        {
            return Err("Nome Host invalido");
        }
        if let Some(port) = port {
            validate_port(port)?;
        }
    }
    Ok(())
}

fn validate_port(port: &str) -> Result<(), &'static str> {
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err("Porta Host invalida");
    }
    let number = port.parse::<u16>().map_err(|_| "Porta Host invalida")?;
    if number == 0 {
        return Err("Porta Host invalida");
    }
    Ok(())
}

fn validate_path(target: &[u8]) -> Result<(), &'static str> {
    if !target.starts_with(b"/") || target.len() > 2048 {
        return Err("Somente request-target na forma origin e suportado");
    }
    if target
        .iter()
        .any(|&b| !(0x21..=0x7e).contains(&b) || b == b'#' || b == b'\\')
    {
        return Err("Request-target contem caractere invalido");
    }
    let path_end = target
        .iter()
        .position(|&b| b == b'?')
        .unwrap_or(target.len());
    let path = &target[..path_end];
    let mut decoded = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        match path[i] {
            b'%' => {
                if i + 2 >= path.len() {
                    return Err("Escape percentual incompleto");
                }
                let hex = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                };
                let a = hex(path[i + 1]).ok_or("Escape percentual invalido")?;
                let b = hex(path[i + 2]).ok_or("Escape percentual invalido")?;
                let value = (a << 4) | b;
                // Rejeita separadores codificados, controles e codificacao em cascata.
                if value == b'/'
                    || value == b'\\'
                    || value == b'%'
                    || value <= 0x20
                    || value >= 0x7f
                {
                    return Err("Escape percentual inseguro na rota");
                }
                decoded.push(value);
                i += 3;
            }
            value => {
                decoded.push(value);
                i += 1;
            }
        }
    }
    if decoded
        .split(|&b| b == b'/')
        .any(|part| part == b"." || part == b"..")
    {
        return Err("Segmento de caminho relativo nao permitido");
    }
    Ok(())
}

/// Valida toda a cabeca HTTP (incluindo CRLFCRLF) antes do Request::parse.
/// Erros geram HTTP 400 e fechamento da conexao.
pub fn validate_request_head(raw: &[u8]) -> Result<(), &'static str> {
    if !raw.ends_with(b"\r\n\r\n") {
        return Err("Cabecalhos sem CRLFCRLF");
    }
    if raw.len() > 8192 {
        return Err("Cabecalhos grandes demais");
    }
    // Nao aceita LF isolado ou CR isolado: proxies podem interpreta-los diferentemente.
    for (i, &b) in raw.iter().enumerate() {
        if b == b'\n' && (i == 0 || raw[i - 1] != b'\r') {
            return Err("LF isolado");
        }
        if b == b'\r' && raw.get(i + 1) != Some(&b'\n') {
            return Err("CR isolado");
        }
        if b == 0 {
            return Err("NUL proibido");
        }
    }
    let mut lines = raw[..raw.len() - 2].split_inclusive(|&b| b == b'\n');
    let first = lines.next().ok_or("Linha de requisicao ausente")?;
    let line = first.strip_suffix(b"\r\n").ok_or("Linha sem CRLF")?;
    let mut words = line.split(|&b| b == b' ');
    let method = words.next().ok_or("Metodo ausente")?;
    let target = words.next().ok_or("Destino ausente")?;
    let version = words.next().ok_or("Versao ausente")?;
    if words.next().is_some() || method.is_empty() || !method.iter().all(|&b| is_tchar(b)) {
        return Err("Linha de requisicao ambigua");
    }
    if version != b"HTTP/1.1" {
        return Err("Apenas HTTP/1.1 suportado");
    }
    validate_path(target)?;

    let mut header_count = 0usize;
    let mut host_count = 0usize;
    let mut length_count = 0usize;
    for raw_line in lines {
        let line = raw_line.strip_suffix(b"\r\n").ok_or("Header sem CRLF")?;

        if line.is_empty() {
            return Err("Linha vazia inesperada nos headers");
        }

        header_count += 1;

        if header_count > 100 {
            return Err("Numero excessivo de headers");
        }

        if line.starts_with(b" ") || line.starts_with(b"\t") {
            return Err("Header com obs-fold (continuacao) proibido");
        }

        let pos = line
            .iter()
            .position(|&b| b == b':')
            .ok_or("Header sem separador")?;
        let name = &line[..pos];
        if name.is_empty() || !name.iter().all(|&b| is_tchar(b)) {
            return Err("Nome de header invalido");
        }
        let value = &line[pos + 1..];
        // Um subconjunto intencionalmente estrito: rejeita HTAB, obs-text e CTLs.
        if value.iter().any(|&b| !(0x20..=0x7e).contains(&b)) {
            return Err("Valor de header nao suportado");
        }
        let trimmed = value.trim_ascii();
        if name.eq_ignore_ascii_case(b"host") {
            host_count += 1;
            if host_count != 1 {
                return Err("Host duplicado");
            }
            parse_host(trimmed)?;
        } else if name.eq_ignore_ascii_case(b"content-length") {
            length_count += 1;
            if length_count != 1
                || trimmed.is_empty()
                || !trimmed.iter().all(|b| b.is_ascii_digit())
            {
                return Err("Content-Length duplicado ou invalido");
            }
        } else if name.eq_ignore_ascii_case(b"transfer-encoding") {
            return Err("Transfer-Encoding nao suportado");
        } else if name.eq_ignore_ascii_case(b"expect") {
            return Err("Expect/100-continue nao suportado");
        } else if name.eq_ignore_ascii_case(b"upgrade") {
            return Err("Upgrade nao suportado");
        }
    }
    if host_count != 1 {
        return Err("HTTP/1.1 exige um unico Host");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_request_head as valid;

    fn head(extra: &str) -> Vec<u8> {
        format!("GET / HTTP/1.1\r\nHost: localhost\r\n{extra}\r\n").into_bytes()
    }

    #[test]
    fn accepts_normal_requests() {
        let request = head("User-Agent: curl/8\r\n");

        assert_eq!(
            valid(&request),
            Ok(()),
            "A requisicao GET com User-Agent deveria ser valida"
        );

        assert_eq!(
            valid(
                b"POST /users HTTP/1.1\r\n\
              Host: localhost:8443\r\n\
              Content-Length: 11\r\n\r\n"
            ),
            Ok(())
        );

        assert_eq!(valid(b"GET / HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n"), Ok(()));
    }

    #[test]
    fn rejects_duplicate_host() {
        assert!(valid(&head("Host: evil.local\r\n")).is_err());
    }
    #[test]
    fn rejects_host_with_at() {
        assert!(valid(b"GET / HTTP/1.1\r\nHost: good@evil\r\n\r\n").is_err());
    }
    #[test]
    fn rejects_header_colon_whitespace() {
        assert!(valid(&head("Host : evil\r\n")).is_err());
    }
    #[test]
    fn rejects_obs_fold() {
        assert!(valid(&head("X-Test: one\r\n two\r\n")).is_err());
    }
    #[test]
    fn rejects_bare_lf() {
        assert!(valid(b"GET / HTTP/1.1\nHost: localhost\n\n").is_err());
    }
    #[test]
    fn rejects_bare_cr() {
        assert!(valid(b"GET / HTTP/1.1\rHost: localhost\r\n\r\n").is_err());
    }
    #[test]
    fn rejects_transfer_encoding() {
        assert!(valid(&head("Transfer-Encoding: chunked\r\n")).is_err());
    }
    #[test]
    fn rejects_multiple_content_lengths() {
        assert!(valid(&head("Content-Length: 0\r\nContent-Length: 0\r\n")).is_err());
    }
    #[test]
    fn rejects_expect() {
        assert!(valid(&head("Expect: 100-continue\r\n")).is_err());
    }
    #[test]
    fn rejects_upgrade() {
        assert!(valid(&head("Upgrade: websocket\r\n")).is_err());
    }
    #[test]
    fn rejects_http_10() {
        assert!(valid(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n").is_err());
    }
    #[test]
    fn rejects_non_origin_target() {
        assert!(valid(b"GET http://example.com/ HTTP/1.1\r\nHost: localhost\r\n\r\n").is_err());
    }
    #[test]
    fn rejects_traversal() {
        for path in [
            "/../secret",
            "/%2e%2E/secret",
            "/x/%2e./secret",
            "/x/%2fetc",
            "/%252e%252e/",
        ] {
            let req = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n");
            assert!(valid(req.as_bytes()).is_err(), "accepted {path}");
        }
    }
    #[test]
    fn rejects_non_ascii_header() {
        let mut bytes = b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Test: ".to_vec();
        bytes.push(0xff);
        bytes.extend_from_slice(b"\r\n\r\n");
        assert!(valid(&bytes).is_err());
    }
    #[test]
    fn rejects_header_without_colon() {
        assert!(valid(&head("Invalid\r\n")).is_err());
    }
}
