//! Testes negativos MQTT v3.1.1 em broker TLS 8901 descartavel.
//! Nao envolve src/main.rs nem broker 8883/8884.
//! So executar via scripts/testar_bridge_bri_negativos_8901.py.
use rumqttc::mqttbytes::v4::SubscribeReasonCode;
use rumqttc::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use rumqttc::{Client, Event, MqttOptions, Packet, QoS, Transport};
use std::{env, fs, io::BufReader, path::Path, sync::Arc};

fn opts(username: &str, password: &str, ca: &Path, id: &str) -> MqttOptions {
    let port: u16 = env::var("BRI_LAB_PORT")
        .expect("porta de laboratorio")
        .parse()
        .expect("porta numerica");
    assert_eq!(port, 8901, "porta precisa ser 8901");
    let mut roots = RootCertStore::empty();
    let input = fs::File::open(ca).expect("CA de teste");
    for item in rustls_pemfile::certs(&mut BufReader::new(input)) {
        roots
            .add(item.expect("PEM de teste"))
            .expect("certificado de teste");
    }
    let tls = ClientConfig::builder_with_provider(Arc::new(
        rumqttc::tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("versoes TLS")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let mut o = MqttOptions::new(id, "localhost", port);
    o.set_credentials(username, password);
    o.set_transport(Transport::tls_with_config(tls.into()));
    o.set_keep_alive(std::time::Duration::from_secs(10));
    o
}
fn pwfile(key: &str) -> String {
    let value = fs::read_to_string(env::var(key).expect("arquivo de credencial temporaria"))
        .expect("ler arquivo de teste");
    value.trim().to_string()
}
fn ca() -> String {
    env::var("BRI_LAB_CA").expect("CA temporaria")
}

#[test]
#[ignore = "apenas no broker 8901 efemero iniciado pelo controlador"]
fn auth_rejeitada() {
    let correct = pwfile("BRI_LAB_BRIDGE_PWFILE");
    let password = format!("invalid-{}", correct);
    let (_, mut conn) = Client::new(
        opts("bridge", &password, Path::new(&ca()), "bri-neg-auth"),
        8,
    );
    match conn.iter().next() {
        Some(Err(_)) => {}
        Some(Ok(Event::Incoming(Packet::ConnAck(_)))) => panic!("broker aceitou senha incorreta"),
        _ => panic!("resultado inesperado na autenticacao negativa"),
    }
}

#[test]
#[ignore = "apenas no broker 8901 efemero iniciado pelo controlador"]
fn ca_nao_confiavel() {
    let password = pwfile("BRI_LAB_BRIDGE_PWFILE");
    let wrong_ca = env::var("BRI_LAB_BAD_CA").expect("CA incorreta de teste");
    let (_, mut conn) = Client::new(
        opts("bridge", &password, Path::new(&wrong_ca), "bri-neg-ca"),
        8,
    );
    match conn.iter().next() {
        Some(Err(_)) => {}
        Some(Ok(Event::Incoming(Packet::ConnAck(_)))) => panic!("TLS aceitou CA nao confiavel"),
        _ => panic!("resultado inesperado no teste de CA nao confiavel"),
    }
}

fn test_subscribe(topic: &str, expected_failure: bool, client_id: &str) {
    let password = pwfile("BRI_LAB_INJECTOR_PWFILE");
    let (client, mut conn) =
        Client::new(opts("injector", &password, Path::new(&ca()), client_id), 8);
    client
        .subscribe(topic, QoS::AtMostOnce)
        .expect("enfileirar SUBSCRIBE");
    for event in conn.iter() {
        match event {
            Ok(Event::Incoming(Packet::SubAck(ack))) => {
                assert_eq!(ack.return_codes.len(), 1, "um unico filtro solicitado");
                let denied = matches!(ack.return_codes[0], SubscribeReasonCode::Failure);
                assert_eq!(
                    denied, expected_failure,
                    "resultado SUBACK diferente do esperado"
                );
                return;
            }
            Err(_) => panic!("conexao falhou antes do SUBACK"),
            _ => {}
        }
    }
    panic!("event loop terminou sem SUBACK");
}

#[test]
#[ignore = "apenas no broker 8901 efemero iniciado pelo controlador"]
fn acl_subscribe_negada() {
    // injector tem permissao WRITE lab/alerts, mas nenhuma READ em bus/#.
    test_subscribe("bus/#", true, "bri-neg-acl");
}
