//! Bridge MQTT <-> bus/1 (laboratorio local).
//!
//! Entrada MQTT: lab/<topico> -> bus/1 <topico>.
//! Saida bus/1:  <topico> -> MQTT bus/<topico>.
//!
//! Topicos distintos e marcador de origem impedem eco/loops. A entrega e
//! best-effort (MQTT QoS 0, sem disco nem replay). Filas sao limitadas.

use crate::messaging::{self, BridgeMessage, Bus};
use rumqttc::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use rumqttc::{Client, Event, MqttOptions, Packet, QoS, Transport};
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;
use std::{fs, io};

// Inscrever somente topicos permitidos pela ACL do broker.
const INBOUND_FILTERS: [&str; 2] = ["lab/alerts", "lab/sensors/#"];
const INBOUND_PREFIX: &str = "lab/";
const OUTBOUND_PREFIX: &str = "bus/";
const BRIDGE_QUEUE_SIZE: usize = 256;
const MQTT_CLIENT_QUEUE_SIZE: usize = 32;

// Regra explicita de topicos que podem atravessar a bridge. NAO e ACL do broker MQTT.
fn allowed_bridge_topic(topic: &str) -> bool {
    messaging::bridge_topic_allowed(topic)
}

fn incoming(topic: &str, payload: &[u8], retained: bool) -> Option<(String, String)> {
    // Nao repassar eventos retidos: evitar replay involuntario na inicializacao.
    if retained {
        return None;
    }
    let route = topic.strip_prefix(INBOUND_PREFIX)?;
    let body = std::str::from_utf8(payload).ok()?;
    if !allowed_bridge_topic(route) || !messaging::valid_body(body) {
        return None;
    }
    Some((route.to_owned(), body.to_owned()))
}

fn outgoing(message: &BridgeMessage) -> Option<(String, Vec<u8>)> {
    if !allowed_bridge_topic(&message.topic) || !messaging::valid_body(&message.body) {
        return None;
    }
    Some((
        format!("{OUTBOUND_PREFIX}{}", message.topic),
        message.body.as_bytes().to_vec(),
    ))
}

pub fn start(bus: Arc<Bus>, broker: SocketAddr, ca_cert: &Path, password: &str) -> io::Result<()> {
    if !broker.ip().is_loopback() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Bridge MQTT exige loopback",
        ));
    }

    let mut options = MqttOptions::new("rust-server-bridge-local", "localhost", broker.port());
    options.set_keep_alive(Duration::from_secs(10));
    options.set_credentials("bridge", password);
    let mut roots = RootCertStore::empty();
    let certfile = fs::File::open(ca_cert)?;
    for cert in rustls_pemfile::certs(&mut BufReader::new(certfile)) {
        roots.add(cert?).map_err(io::Error::other)?;
    }
    let client_tls = ClientConfig::builder_with_provider(std::sync::Arc::new(
        rumqttc::tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(io::Error::other)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    options.set_transport(Transport::tls_with_config(client_tls.into()));
    options.set_max_packet_size(8192, 8192);
    options.set_clean_session(true);
    let (client, mut connection) = Client::new(options, MQTT_CLIENT_QUEUE_SIZE);
    // Registro antes do polling da conexao: a inscricao inicial e enfileirada.
    for topic in INBOUND_FILTERS {
        client
            .subscribe(topic, QoS::AtMostOnce)
            .map_err(io::Error::other)?;
    }

    let (tx, rx) = mpsc::sync_channel::<BridgeMessage>(BRIDGE_QUEUE_SIZE);
    let publisher = client.clone();
    thread::Builder::new()
        .name("mqtt-bridge-out".into())
        .spawn(move || {
            let mut errors: u64 = 0;
            for message in rx {
                let Some((topic, payload)) = outgoing(&message) else {
                    continue;
                };
                // Nao bloquear o worker enquanto o broker estiver offline.
                // Erros e overflow sao observaveis no stderr, sem memoria ilimitada.
                if let Err(err) = publisher.try_publish(topic, QoS::AtMostOnce, false, payload) {
                    errors += 1;
                    if errors == 1 || errors % 100 == 0 {
                        eprintln!("[BRIDGE] falha ao enfileirar no cliente MQTT ({errors}): {err}");
                    }
                }
            }
        })?;

    bus.attach_bridge(tx)?;
    thread::Builder::new()
        .name("mqtt-bridge-in".into())
        .spawn(move || {
            let mut errors: u64 = 0;
            for notification in connection.iter() {
                match notification {
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        eprintln!("[BRIDGE] MQTT conectado em {broker}");
                        // Reinscrever apos reconexao: sessoes MQTT sao limpas.
                        for topic in INBOUND_FILTERS {
                            if let Err(err) = client.try_subscribe(topic, QoS::AtMostOnce) {
                                eprintln!("[BRIDGE] nao foi possivel reinscrever: {err}");
                            }
                        }
                    }
                    Ok(Event::Incoming(Packet::Publish(message))) => {
                        let Some((topic, body)) =
                            incoming(&message.topic, &message.payload, message.retain)
                        else {
                            continue;
                        };
                        if let Err(err) = bus.publish_from_mqtt(&topic, &body) {
                            eprintln!("[BRIDGE] MQTT -> bus rejeitado: {err}");
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        errors += 1;
                        if errors == 1 || errors % 100 == 0 {
                            eprintln!(
                                "[BRIDGE] MQTT desconectado/tentando reconectar ({errors}): {err}"
                            );
                        }
                        thread::sleep(Duration::from_secs(1));
                    }
                }
            }
            eprintln!("[BRIDGE] event loop terminou inesperadamente");
            std::process::exit(1);
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapeia_lab_para_bus() {
        assert_eq!(
            incoming("lab/alerts", b"servidor online", false),
            Some(("alerts".to_owned(), "servidor online".to_owned()))
        );
        assert_eq!(
            incoming("lab/sensors/temp", b"25", false),
            Some(("sensors/temp".to_owned(), "25".to_owned()))
        );
    }

    #[test]
    fn so_aceita_mensagens_validas_e_nao_retidas() {
        assert!(incoming("bus/alerts", b"teste", false).is_none());
        assert!(incoming("lab/alerts", b"retida", true).is_none());
        assert!(incoming("lab/alerts", b"ola\nmundo", false).is_none());
        assert!(incoming("lab/a/#", b"x", false).is_none());
        assert!(incoming("lab/private/secret", b"x", false).is_none());
        assert!(incoming("lab/", b"x", false).is_none());
        assert!(incoming("lab/alerts", &[0xff], false).is_none());
        assert!(incoming("lab/alerts", &vec![b'x'; 2049], false).is_none());
    }

    #[test]
    fn topicos_direcionais_nao_formam_ciclo() {
        let output = BridgeMessage {
            topic: "alerts".to_owned(),
            body: "evento".to_owned(),
        };
        let (topic, body) = outgoing(&output).unwrap();
        assert_eq!(topic, "bus/alerts");
        assert_eq!(body, b"evento");
        assert!(incoming(&topic, &body, false).is_none());
    }
}
