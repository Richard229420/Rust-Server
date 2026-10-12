pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self::with_content_type(status, "text/html; charset=utf-8", body)
    }

    pub fn with_content_type(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,

            headers: vec![("Content-Type".to_string(), content_type.to_string())],

            body: body.into(),
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let reason = match self.status {
            200 => "OK",
            400 => "Bad Request",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            413 => "Payload Too Large",
            500 => "Internal Server Error",
            503 => "Service Unavailable",
            _ => "Unknown",
        };

        let mut response = format!("HTTP/1.1 {} {}\r\n", self.status, reason);

        for (key, value) in &self.headers {
            response.push_str(&format!("{key}: {value}\r\n"));
        }

        response.push_str(&format!("Content-Length: {}\r\n", self.body.len()));

        response.push_str("Connection: close\r\n");
        response.push_str("\r\n");

        let mut bytes = response.into_bytes();

        bytes.extend_from_slice(&self.body);

        bytes
    }
}
