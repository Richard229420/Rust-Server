// Cliente Rust para exercitar PUB/SUB TCP e PUB UDP no laboratorio.
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(String::as_str);
    let token_key = match mode {
        Some("tcp-sub") => "RUST_SERVER_BUS_READ_TOKEN",
        Some("tcp-pub") => "RUST_SERVER_BUS_WRITE_TOKEN",
        Some("udp-pub") => "RUST_SERVER_BUS_TOKEN",
        _ => "RUST_SERVER_BUS_TOKEN",
    };
    let token = env::var(token_key).map_err(|_| io::Error::other(format!("Defina {token_key}")))?;
    match args.get(1).map(String::as_str) {
        Some("tcp-sub") if args.len() == 3 => {
            let mut socket = connect_tls()?;
            // Completa o handshake TLS sob o limite de 5 segundos. A conexao
            // pub/sub fica aberta sem mensagens por tempo indeterminado.
            socket.conn.complete_io(&mut socket.sock)?;
            socket.sock.set_read_timeout(None)?;
            socket.write_all(format!("AUTH {token}\nSUB {}\n", args[2]).as_bytes())?;
            let reader = BufReader::new(socket);
            for line in reader.lines() {
                println!("{}", line?);
            }
        }
        Some("tcp-pub") if args.len() >= 4 => {
            let mut socket = connect_tls()?;
            socket.sock.set_read_timeout(Some(Duration::from_secs(3)))?;
            socket.write_all(
                format!(
                    "AUTH {token}\nPUB {} {}\nQUIT\n",
                    args[2],
                    args[3..].join(" ")
                )
                .as_bytes(),
            )?;
            let reader = BufReader::new(socket);
            for line in reader.lines() {
                println!("{}", line?);
            }
        }
        Some("udp-pub") if args.len() >= 4 => {
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.set_read_timeout(Some(Duration::from_secs(3)))?;
            let command = format!("PUB {token} {} {}", args[2], args[3..].join(" "));
            socket.send_to(command.as_bytes(), "127.0.0.1:7002")?;
            let mut response = [0_u8; 512];
            let (len, _) = socket.recv_from(&mut response)?;
            println!("{}", String::from_utf8_lossy(&response[..len]));
        }
        _ => {
            eprintln!("Uso: cargo run --example bus_client -- tcp-sub TOPICO");
            eprintln!("     cargo run --example bus_client -- tcp-pub TOPICO MENSAGEM");
            eprintln!("     cargo run --example bus_client -- udp-pub TOPICO MENSAGEM");
            std::process::exit(2);
        }
    }
    Ok(())
}

fn connect_tls() -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let cert_path = env::var("RUST_SERVER_TLS_CA").unwrap_or_else(|_| "certs/ca.crt".into());
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut io::BufReader::new(File::open(Path::new(&cert_path))?)) {
        roots.add(cert?).map_err(io::Error::other)?;
    }
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let stream = TcpStream::connect("127.0.0.1:7001")?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let conn = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from("localhost").map_err(io::Error::other)?,
    )
    .map_err(io::Error::other)?;
    Ok(StreamOwned::new(conn, stream))
}
