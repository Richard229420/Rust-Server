//! BRI negativo v2: TLS, senha e prova de ACL de leitura por entrega efetiva.
//! Somente broker efemero 127.0.0.1:8901, controlador Python v2.
use rumqttc::mqttbytes::v4::SubscribeReasonCode;
use rumqttc::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use rumqttc::{Client, Connection, Event, MqttOptions, Packet, QoS, Transport};
use std::{
    env, fs,
    io::BufReader,
    path::Path,
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

fn opts(username: &str, password: &str, ca: &Path, id: &str) -> MqttOptions {
    let port: u16 = env::var("BRI_LAB_PORT")
        .expect("porta de laboratorio")
        .parse()
        .expect("porta numerica");
    assert_eq!(port, 8901, "somente porta descartavel 8901");
    let mut roots = RootCertStore::empty();
    let input = fs::File::open(ca).expect("CA descartavel");
    for item in rustls_pemfile::certs(&mut BufReader::new(input)) {
        roots.add(item.expect("certificado PEM")).expect("CA TLS");
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
    o.set_keep_alive(Duration::from_secs(10));
    o
}

fn pwfile(key: &str) -> String {
    fs::read_to_string(env::var(key).expect("arquivo de senha descartavel"))
        .expect("leitura de senha temporaria")
        .trim()
        .to_string()
}
fn ca() -> String {
    env::var("BRI_LAB_CA").expect("CA temporaria")
}

#[test]
#[ignore = "executado somente pelo controlador Python do broker efemero"]
fn auth_rejeitada() {
    let incorrect = format!("bad-{}", pwfile("BRI_LAB_BRIDGE_PWFILE"));
    let (_, mut conn) = Client::new(
        opts("bridge", &incorrect, Path::new(&ca()), "bri-v2-auth"),
        8,
    );
    match conn.iter().next() {
        Some(Err(_)) => {}
        Some(Ok(Event::Incoming(Packet::ConnAck(_)))) => panic!("senha incorreta aceita"),
        _ => panic!("resposta de autenticacao inesperada"),
    }
}

#[test]
#[ignore = "executado somente pelo controlador Python do broker efemero"]
fn ca_nao_confiavel() {
    let pass = pwfile("BRI_LAB_BRIDGE_PWFILE");
    let bad_ca = env::var("BRI_LAB_BAD_CA").expect("CA errada temporaria");
    let (_, mut conn) = Client::new(opts("bridge", &pass, Path::new(&bad_ca), "bri-v2-ca"), 8);
    match conn.iter().next() {
        Some(Err(_)) => {}
        Some(Ok(Event::Incoming(Packet::ConnAck(_)))) => panic!("CA nao confiavel aceita"),
        _ => panic!("resposta TLS inesperada"),
    }
}

#[derive(Debug)]
enum Seen {
    SubAck { denied: bool, count: usize },
    PubAck,
    Publish { topic: String, payload: Vec<u8> },
    Error,
}

fn pump(mut conn: Connection) -> mpsc::Receiver<Seen> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for event in conn.iter() {
            let status = match event {
                Ok(Event::Incoming(Packet::SubAck(ack))) => Some(Seen::SubAck {
                    denied: ack
                        .return_codes
                        .iter()
                        .any(|c| matches!(c, SubscribeReasonCode::Failure)),
                    count: ack.return_codes.len(),
                }),
                Ok(Event::Incoming(Packet::PubAck(_))) => Some(Seen::PubAck),
                Ok(Event::Incoming(Packet::Publish(msg))) => Some(Seen::Publish {
                    topic: msg.topic,
                    payload: msg.payload.to_vec(),
                }),
                Err(_) => Some(Seen::Error),
                _ => None,
            };
            if let Some(status) = status {
                if tx.send(status).is_err() {
                    break;
                }
            }
        }
    });
    rx
}

fn wait_suback(rx: &mpsc::Receiver<Seen>, label: &str) -> bool {
    let end = Instant::now() + Duration::from_secs(8);
    loop {
        let remaining = end.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "{label}: faltou SUBACK");
        match rx.recv_timeout(remaining).expect("SUBACK nao chegou") {
            Seen::SubAck { denied, count } => {
                assert_eq!(count, 1, "{label}: resultado inesperado");
                return denied;
            }
            Seen::Error => panic!("{label}: erro MQTT antes do SUBACK"),
            other => panic!("{label}: evento inesperado {other:?}"),
        }
    }
}

#[test]
#[ignore = "executado somente pelo controlador Python do broker efemero"]
fn acl_entrega_negada() {
    // O usuario injector pode publicar lab/alerts, mas NAO pode ler bus/#.
    // O usuario auditor pode ler bus/alerts; serve como controle positivo
    // para provar que houve uma publicacao real do mesmo topico.
    let ca = ca();
    let (auditor, aud_conn) = Client::new(
        opts(
            "auditor",
            &pwfile("BRI_LAB_AUDITOR_PWFILE"),
            Path::new(&ca),
            "bri-v2-auditor",
        ),
        8,
    );
    let aud_rx = pump(aud_conn);
    auditor
        .subscribe("bus/alerts", QoS::AtMostOnce)
        .expect("subscribe auditor");
    assert!(!wait_suback(&aud_rx, "auditor"), "controle positivo negado");

    let (injector, inj_conn) = Client::new(
        opts(
            "injector",
            &pwfile("BRI_LAB_INJECTOR_PWFILE"),
            Path::new(&ca),
            "bri-v2-injector",
        ),
        8,
    );
    let inj_rx = pump(inj_conn);
    injector
        .subscribe("bus/#", QoS::AtMostOnce)
        .expect("subscribe injector");
    // Em ACL classica, SUBACK de sucesso nao implica permissao para receber.
    // Aceitamos o ACK sucesso/falha, mas exigimos BLOQUEIO efetivo da entrega.
    let _denied_at_suback = wait_suback(&inj_rx, "injector");

    let (bridge, bridge_conn) = Client::new(
        opts(
            "bridge",
            &pwfile("BRI_LAB_BRIDGE_PWFILE"),
            Path::new(&ca),
            "bri-v2-publisher",
        ),
        8,
    );
    let bridge_rx = pump(bridge_conn);
    let payload = env::var("BRI_LAB_NONCE").expect("marcador de teste descartavel");
    assert_eq!(payload.len(), 32, "marcador inesperado");
    bridge
        .publish("bus/alerts", QoS::AtLeastOnce, false, payload.as_bytes())
        .expect("publicar em bus/alerts");

    // Controle positivo: broker realmente entregou a publicacao ao leitor autorizado.
    let end = Instant::now() + Duration::from_secs(8);
    let mut seen = false;
    while Instant::now() < end {
        match aud_rx.recv_timeout(end.saturating_duration_since(Instant::now())) {
            Ok(Seen::Publish {
                topic,
                payload: got,
            }) => {
                assert_eq!(topic, "bus/alerts");
                assert_eq!(got.as_slice(), payload.as_bytes());
                seen = true;
                break;
            }
            Ok(Seen::Error) => panic!("auditor perdeu a conexao"),
            Ok(other) => panic!("auditor recebeu evento inesperado: {other:?}"),
            Err(_) => break,
        }
    }
    assert!(seen, "controle positivo: auditor nao recebeu a publicacao");

    // Controle da publicacao: QoS1 confirmou a operacao (nao seria suficiente sozinho).
    let end = Instant::now() + Duration::from_secs(8);
    loop {
        let remain = end.saturating_duration_since(Instant::now());
        assert!(!remain.is_zero(), "faltou PUBACK");
        match bridge_rx
            .recv_timeout(remain)
            .expect("publisher nao recebeu PUBACK")
        {
            Seen::PubAck => break,
            Seen::Error => panic!("publisher desconectado"),
            other => panic!("publisher recebeu evento inesperado: {other:?}"),
        }
    }

    // Controle negativo: o cliente sem READ nao pode receber a MESMA mensagem.
    // Espera limitada, sem deduzir autorizacao apenas pela resposta SUBACK.
    match inj_rx.recv_timeout(Duration::from_millis(1800)) {
        Ok(Seen::Publish { topic, .. }) => panic!("vazamento ACL para injector: {topic}"),
        Ok(Seen::Error) => panic!("injector desconectou; resultado de ACL inconclusivo"),
        Ok(other) => panic!("injector recebeu evento inesperado: {other:?}"),
        Err(mpsc::RecvTimeoutError::Timeout) => {}
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!("injetor perdeu event loop"),
    }
    // As threads do event loop terminam com o processo isolado do teste.
}
