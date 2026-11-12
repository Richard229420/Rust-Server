//! Executavel efemero de observacao da bridge.rs REAL; nao integra o binario server.
//! Copiado para scratch privado junto com src/bridge.rs. Nenhum endereco configuravel.
use std::fs;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};

mod messaging {
    use super::*;

    #[derive(Clone)]
    pub struct BridgeMessage { pub topic: String, pub body: String }

    // Observador isolado: verifica a chamada da bridge para o bus, sem ativar TCP-TLS.
    pub struct Bus { tx: Mutex<Option<mpsc::SyncSender<BridgeMessage>>> }
    impl Bus {
        pub fn new() -> Self { Self { tx: Mutex::new(None) } }
        pub fn attach_bridge(&self, tx: mpsc::SyncSender<BridgeMessage>) -> io::Result<()> {
            let mut slot = self.tx.lock().map_err(|_| io::Error::other("mutex"))?;
            if slot.is_some() { return Err(io::Error::other("bridge duplicada")); }
            *slot = Some(tx);
            Ok(())
        }
        pub fn publish_from_mqtt(&self, topic: &str, body: &str) -> Result<(), &'static str> {
            if !bridge_topic_allowed(topic) || !valid_body(body) { return Err("entrada invalida"); }
            println!("IN {topic} {body}");
            io::stdout().flush().map_err(|_| "stdout indisponivel")?;
            Ok(())
        }
        pub fn publish_outgoing(&self, body: &str) -> io::Result<()> {
            if !valid_body(body) { return Err(io::Error::other("corpo invalido")); }
            self.tx.lock().map_err(|_| io::Error::other("mutex"))?
                .as_ref().ok_or_else(|| io::Error::other("bridge nao iniciada"))?
                .send(BridgeMessage { topic: "alerts".into(), body: body.into() })
                .map_err(|_| io::Error::other("fila fechada"))
        }
    }
    pub fn valid_body(s: &str) -> bool {
        !s.is_empty() && s.len() <= 2048 && !s.chars().any(char::is_control)
    }
    pub fn bridge_topic_allowed(topic: &str) -> bool {
        topic == "alerts" || topic.starts_with("sensors/") &&
            topic.len() <= 64 && topic.bytes().all(|c| c.is_ascii_alphanumeric() ||
                matches!(c, b'/' | b'.' | b'_' | b'-')) && !topic.contains("//")
    }
}
#[path = "bridge.rs"] mod bridge;

fn private_password(path: &Path) -> io::Result<String> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.nlink() != 1 ||
       meta.mode() & 0o777 != 0o600 || meta.uid() != unsafe { libc_geteuid() } {
        return Err(io::Error::other("arquivo de senha de ensaio inseguro"));
    }
    let password = fs::read_to_string(path)?;
    if !(32..=128).contains(&password.len()) || !password.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return Err(io::Error::other("senha de ensaio invalida"));
    }
    Ok(password)
}
// libc sem dependencia: syscall POSIX de euid, disponivel apenas em Linux.
unsafe extern "C" { #[link_name = "geteuid"] fn libc_geteuid() -> u32; }

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 { return Err(io::Error::other("uso: probe CA senha-privada")); }
    let ca = Path::new(&args[1]);
    let password = private_password(Path::new(&args[2]))?;
    let addr: SocketAddr = "127.0.0.1:8895".parse().map_err(io::Error::other)?;
    let bus = Arc::new(messaging::Bus::new());
    bridge::start(Arc::clone(&bus), addr, ca, &password)?;
    drop(password);
    println!("READY");
    io::stdout().flush()?;
    for line in io::stdin().lock().lines() {
        let line = line?;
        if line == "STOP" { break; }
        if let Some(payload) = line.strip_prefix("PUB ") {
            if payload.starts_with("c1-") && payload.len() < 80 &&
                payload.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
                bus.publish_outgoing(payload)?;
                println!("QUEUED {payload}");
                io::stdout().flush()?;
            } else { return Err(io::Error::other("payload invalido")); }
        } else { return Err(io::Error::other("comando desconhecido")); }
    }
    Ok(())
}
