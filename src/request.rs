use std::collections::HashMap;

#[derive(Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    //Versão HTTP preservada para uso futuro
    #[allow(dead_code)]
    pub version: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn content_length(headers: &HashMap<String, String>) -> Result<usize, String> {
        match headers.get("content-length") {
            Some(value) => {
                if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Err("Content-Length inválido.".to_string());
                }

                value
                    .parse::<usize>()
                    .map_err(|_| "Content-Length excede o valor suportado.".to_string())
            }

            None => Ok(0),
        }
    }
    pub fn parse(buffer: &[u8]) -> Result<Self, String> {
        let request = String::from_utf8_lossy(buffer);

        let (head, body) = match request.split_once("\r\n\r\n") {
            Some((head, body)) => (head, body.as_bytes().to_vec()),
            None => (request.as_ref(), Vec::new()),
        };

        let mut lines = head.lines();

        let request_line = lines.next().ok_or_else(|| "Requisição vazia".to_string())?;

        let mut parts = request_line.split_whitespace();

        let method = parts
            .next()
            .ok_or_else(|| "Método HTTP ausente".to_string())?
            .to_string();

        let path = parts
            .next()
            .ok_or_else(|| "Caminho HTTP ausente".to_string())?
            .to_string();

        let version = parts
            .next()
            .ok_or_else(|| "Versão HTTP ausente".to_string())?
            .to_string();

        if parts.next().is_some() {
            return Err("Request Line possui campos extras.".to_string());
        }

        if version != "HTTP/1.1" {
            return Err(format!("Versão HTTP não suportada: {version}"));
        }

        let mut headers = HashMap::new();
        let mut header_count = 0;

        for line in lines {
            header_count += 1;

            if header_count > 100 {
                return Err("Quantidade máxima de headers excedida.".to_string());
            }

            if line.len() > 8192 {
                return Err("Header HTTP excede o tamanho máximo permitido.".to_string());
            }

            let (key, value) = line
                .split_once(':')
                .ok_or_else(|| format!("Header HTTP malformado: {line}"))?;

            let key = key.trim();

            if key.is_empty() {
                return Err("Nome do header HTTP está vazio.".to_string());
            }

            let key = key.to_ascii_lowercase();
            let value = value.trim().to_string();

            if key == "content-length" && headers.contains_key(&key) {
                return Err("Header Content-Length duplicado.".to_string());
            }

            if key == "transfer-encoding" {
                return Err("Transfer-Enconding não suportado.".to_string());
            }

            headers.insert(key, value);
        }

        if !headers.contains_key("host") {
            return Err("Header Host obrigatório no HTTP/1.1".to_string());
        }

        let _content_length = Self::content_length(&headers)?;

        Ok(Self {
            method,
            path,
            version,
            headers,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_length_valido() {
        let mut headers = HashMap::new();

        headers.insert("content-length".to_string(), "11".to_string());

        assert_eq!(Request::content_length(&headers), Ok(11));
    }

    #[test]
    fn content_length_ausente() {
        let headers = HashMap::new();

        assert_eq!(Request::content_length(&headers), Ok(0));
    }

    #[test]
    fn content_length_invalido() {
        let mut headers = HashMap::new();

        headers.insert("content-length".to_string(), "abc".to_string());

        assert!(Request::content_length(&headers).is_err());
    }

    #[test]
    fn content_length_negativo() {
        let mut headers = HashMap::new();

        headers.insert("content-length".to_string(), "-10".to_string());

        assert!(Request::content_length(&headers).is_err());
    }

    #[test]
    fn content_length_muito_grande() {
        let mut headers = HashMap::new();

        headers.insert(
            "content-length".to_string(),
            "999999999999999999999999999999999".to_string(),
        );

        assert!(Request::content_length(&headers).is_err());
    }
    #[test]
    fn content_length_duplicado() {
        let request = b"POST /users HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 10\r\n\
Content-Length: 100\r\n\
\r\n";

        assert!(Request::parse(request).is_err());
    }

    #[test]
    fn transfer_encoding_nao_suportado() {
        let request = b"POST /users HTTP/1.1\r\n\
Host: localhost\r\n\
Transfer-Encoding: chunked\r\n\
\r\n";

        assert!(Request::parse(request).is_err());
    }

    #[test]
    fn content_length_invalido_na_requisicao() {
        let request = b"POST /users HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: abc\r\n\
\r\n";

        assert!(Request::parse(request).is_err());
    }

    #[test]
    fn content_length_valido_na_requisicao() {
        let request = b"POST /users HTTP/1.1\r\n\
Host: localhost\r\n\
Content-Length: 11\r\n\
\r\n";

        assert!(Request::parse(request).is_ok());
    }
}
