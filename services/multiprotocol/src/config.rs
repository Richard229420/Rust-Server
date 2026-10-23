use std::env;
use std::error::Error;
use std::net::SocketAddr;
use std::path::PathBuf;

pub struct Settings {
    pub https_addr: SocketAddr,
    pub upstream_addr: SocketAddr,
    pub tcp_addr: SocketAddr,
    pub udp_addr: SocketAddr,
    pub tls_cert: PathBuf,
    pub tls_ca: PathBuf,
    pub tls_key: PathBuf,
    pub mqtt_addr: SocketAddr,
    pub bus_token: String,
    pub mqtt_bridge_password: String,
    pub bus_read_token: String,
    pub bus_write_token: String,
    pub enable_legacy_udp: bool,
}

impl Settings {
    pub fn from_env() -> Result<Self, Box<dyn Error + Send + Sync>> {
        fn addr(key: &str, default: &str) -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
            Ok(env::var(key)
                .unwrap_or_else(|_| default.to_owned())
                .parse()?)
        }
        let bus_token = env::var("RUST_SERVER_BUS_TOKEN")
            .map_err(|_| "Defina RUST_SERVER_BUS_TOKEN (minimo 16 caracteres) antes de iniciar")?;
        if bus_token.len() < 16
            || bus_token
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
        {
            return Err(
                "RUST_SERVER_BUS_TOKEN deve ter 16+ caracteres e nenhum espaco/controle".into(),
            );
        }
        fn secret(key: &str) -> Result<String, Box<dyn Error + Send + Sync>> {
            let value = env::var(key).map_err(|_| {
                format!("Defina {key} (use scripts/setup_phase8.sh e source scripts/env_phase8.sh)")
            })?;
            if value.len() < 32
                || value.len() > 128
                || !value.bytes().all(|b| b.is_ascii_alphanumeric())
            {
                return Err(format!(
                    "{key} exige 32..128 caracteres alfanumericos sem quebras de linha"
                )
                .into());
            }
            Ok(value)
        }
        let mqtt_bridge_password = secret("RUST_SERVER_MQTT_BRIDGE_PASSWORD")?;
        let bus_read_token = secret("RUST_SERVER_BUS_READ_TOKEN")?;
        let bus_write_token = secret("RUST_SERVER_BUS_WRITE_TOKEN")?;
        if bus_read_token == bus_write_token
            || bus_read_token == bus_token
            || bus_write_token == bus_token
        {
            return Err("Credenciais devem ser distintas".into());
        }
        let enable_legacy_udp = env::var("RUST_SERVER_ENABLE_LEGACY_UDP").as_deref() == Ok("1");
        let upstream_addr = addr("RUST_SERVER_HTTP_UPSTREAM", "127.0.0.1:8080")?;
        if !upstream_addr.ip().is_loopback() {
            return Err("Backend HTTP deve escutar em loopback".into());
        }
        let https_addr = addr("RUST_SERVER_HTTPS_ADDR", "127.0.0.1:8443")?;
        let tcp_addr = addr("RUST_SERVER_TCP_ADDR", "127.0.0.1:7001")?;
        let udp_addr = addr("RUST_SERVER_UDP_ADDR", "127.0.0.1:7002")?;
        let mqtt_addr = addr("RUST_SERVER_MQTT_ADDR", "127.0.0.1:8883")?;
        if mqtt_addr != "127.0.0.1:8883".parse::<SocketAddr>()? {
            return Err("MQTT deve permanecer em 127.0.0.1:8883 nesta fase".into());
        }
        // TCP exige TLS; o protocolo UDP legado nao possui TLS e e bloqueado fora do loopback.
        if !tcp_addr.ip().is_loopback() || !udp_addr.ip().is_loopback() {
            return Err("Mensageria TCP/UDP deve ficar em loopback (use VPN/TLS externo)".into());
        }
        if upstream_addr == https_addr
            || https_addr == tcp_addr
            || tcp_addr == udp_addr
            || udp_addr == https_addr
            || udp_addr == upstream_addr
            || tcp_addr == upstream_addr
        {
            return Err("Enderecos de escuta e backend nao podem coincidir".into());
        }
        Ok(Self {
            https_addr,
            upstream_addr,
            tcp_addr,
            udp_addr,
            tls_cert: env::var_os("RUST_SERVER_TLS_CERT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("certs/localhost.crt")),
            tls_ca: env::var_os("RUST_SERVER_TLS_CA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("certs/ca.crt")),
            tls_key: env::var_os("RUST_SERVER_TLS_KEY")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("certs/localhost.key")),
            mqtt_addr,
            bus_token,
            mqtt_bridge_password,
            bus_read_token,
            bus_write_token,
            enable_legacy_udp,
        })
    }
}
