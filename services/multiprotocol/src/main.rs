mod bridge;
mod config;
mod https;
mod messaging;
mod mqtt;

use std::error::Error;
use std::sync::Arc;
use std::thread;

fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let cfg = config::Settings::from_env()?;
    let tls = https::load_tls(&cfg.tls_cert, &cfg.tls_key)?;
    let bus = Arc::new(messaging::Bus::with_roles(
        cfg.bus_token,
        cfg.bus_read_token,
        cfg.bus_write_token,
    ));
    let tcp_tls = Arc::clone(&tls);

    let tcp_addr = cfg.tcp_addr;
    let tcp_bus = Arc::clone(&bus);
    let tcp = thread::Builder::new()
        .name("bus-tcp".into())
        .spawn(move || {
            if let Err(err) = messaging::tcp_listener(tcp_addr, tcp_bus, tcp_tls) {
                eprintln!("[TCP] fatal: {err}");
                std::process::exit(1);
            }
        })?;

    if cfg.enable_legacy_udp {
        eprintln!(
            "[SEGURANCA] ATENCAO: UDP legado local habilitado, sem TLS; nao usar dados sensiveis"
        );
        let udp_addr = cfg.udp_addr;
        let udp_bus = Arc::clone(&bus);
        thread::Builder::new()
            .name("bus-udp-legacy".into())
            .spawn(move || {
                if let Err(err) = messaging::udp_listener(udp_addr, udp_bus) {
                    eprintln!("[UDP] fatal: {err}");
                    std::process::exit(1);
                }
            })?;
    }

    let broker_addr = mqtt::external_broker(cfg.mqtt_addr)?;
    bridge::start(
        Arc::clone(&bus),
        broker_addr,
        &cfg.tls_ca,
        &cfg.mqtt_bridge_password,
    )?;
    eprintln!("[MQTT] broker Mosquitto EXTERNO esperado em {broker_addr} (TLS + ACL, verificar processo separado)");
    eprintln!("[BRIDGE] MQTT lab/<topico> -> bus/1 <topico>; bus/1 <topico> -> MQTT bus/<topico>");
    eprintln!(
        "[HTTPS] https://{} -> http://{}",
        cfg.https_addr, cfg.upstream_addr
    );
    eprintln!(
        "[TCP-TLS] {} (loopback; ACL de papeis; tokens obrigatorios)",
        cfg.tcp_addr
    );
    eprintln!(
        "[UDP legado] {}",
        if cfg.enable_legacy_udp {
            "habilitado somente em loopback"
        } else {
            "desabilitado"
        }
    );

    // O gateway TLS preserva a API REST e os handlers da versao 6.4 no backend.
    https::serve(cfg.https_addr, cfg.upstream_addr, tls)?;
    tcp.join().expect("thread TCP entrou em panico");

    Ok(())
}
