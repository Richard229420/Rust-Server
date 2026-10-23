//! Fase 8.2: broker externo Mosquitto. Sem broker embutido e sem bypass de ACL.
use std::error::Error;
use std::net::SocketAddr;

pub fn external_broker(addr: SocketAddr) -> Result<SocketAddr, Box<dyn Error + Send + Sync>> {
    if addr != "127.0.0.1:8883".parse::<SocketAddr>()? {
        return Err("Broker externo deve estar em 127.0.0.1:8883".into());
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restringe_broker_ao_loopback_tls() {
        assert!(external_broker("127.0.0.1:8883".parse().unwrap()).is_ok());
        assert!(external_broker("127.0.0.1:1883".parse().unwrap()).is_err());
        assert!(external_broker("0.0.0.0:8883".parse().unwrap()).is_err());
    }
}
