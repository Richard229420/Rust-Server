//! Ensaio isolado: carrega o src/bridge.rs real, com adaptador de bus apenas para teste.
//! Ignorado por padrao; invocado somente pelo controlador Python da Fase 8.4.
use std::{
    env, fs,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

// O adaptador de bus NAO e a implementacao real de messaging::Bus.
// O ensaio cobre bridge::start e o caminho MQTT->bus, nao a ACL interna de bus/1.
mod messaging {
    use std::{
        io,
        sync::{mpsc::SyncSender, Mutex},
    };

    #[derive(Debug)]
    pub struct BridgeMessage {
        pub topic: String,
        pub body: String,
    }

    #[derive(Default)]
    pub struct Bus {
        pub received: Mutex<Vec<String>>,
        sender: Mutex<Option<SyncSender<BridgeMessage>>>,
    }

    impl Bus {
        pub fn attach_bridge(&self, sender: SyncSender<BridgeMessage>) -> io::Result<()> {
            *self.sender.lock().expect("mutex sender") = Some(sender);
            Ok(())
        }
        pub fn publish_from_mqtt(&self, topic: &str, _body: &str) -> io::Result<()> {
            self.received
                .lock()
                .expect("mutex received")
                .push(topic.to_owned());
            Ok(())
        }
    }

    pub fn bridge_topic_allowed(topic: &str) -> bool {
        topic == "alerts" || topic.starts_with("sensors/")
    }
    pub fn valid_body(body: &str) -> bool {
        !body.is_empty()
            && body.len() <= 2048
            && !body.chars().any(|c| matches!(c, '\r' | '\n' | '\0'))
    }
}

#[path = "../src/bridge.rs"]
mod bridge;

use rumqttc::tokio_rustls::rustls::{ClientConfig, RootCertStore};
use rumqttc::{Client, Event, MqttOptions, Packet, QoS, Transport};
use std::io::BufReader;

fn roots(ca: &Path) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    let f = fs::File::open(ca).expect("CA isolada");
    for c in rustls_pemfile::certs(&mut BufReader::new(f)) {
        roots.add(c.expect("PEM")).expect("CA valida");
    }
    roots
}

fn publish_injected(port: u16, ca: &Path, passwd: &str) {
    let mut options = MqttOptions::new("bri-injector-descartavel", "localhost", port);
    options.set_keep_alive(Duration::from_secs(10));
    options.set_credentials("injector", passwd);
    let tls = ClientConfig::builder_with_provider(Arc::new(
        rumqttc::tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("tls versions")
    .with_root_certificates(roots(ca))
    .with_no_client_auth();
    options.set_transport(Transport::tls_with_config(tls.into()));
    let (client, mut connection) = Client::new(options, 16);
    client
        .publish("lab/alerts", QoS::AtLeastOnce, false, "bri-ensaio")
        .expect("enfileirar teste");
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        for event in connection.iter() {
            match event {
                Ok(Event::Incoming(Packet::PubAck(_))) => {
                    let _ = tx.send(true);
                    break;
                }
                Err(_) => {
                    let _ = tx.send(false);
                    break;
                }
                _ => {}
            }
        }
    });
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(10)).ok(),
        Some(true),
        "injetor QoS1 nao foi confirmado"
    );
}

#[test]
#[ignore = "somente pelo controlador BRI com broker efemero em 8901"]
fn integra_bridge_real_em_broker_descartavel() {
    let port = env::var("BRI_LAB_PORT")
        .expect("porta")
        .parse::<u16>()
        .expect("porta numerica");
    assert_eq!(port, 8901, "porta de ensaio inesperada");
    let ca = env::var("BRI_LAB_CA").expect("CA");
    let bridge_pw = fs::read_to_string(env::var("BRI_LAB_BRIDGE_PWFILE").expect("pwfile bridge"))
        .expect("pwfile bridge");
    let inject_pw =
        fs::read_to_string(env::var("BRI_LAB_INJECTOR_PWFILE").expect("pwfile injector"))
            .expect("pwfile injector");
    let ca = Path::new(&ca);
    let bus = Arc::new(messaging::Bus::default());
    let broker = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    bridge::start(Arc::clone(&bus), broker, ca, bridge_pw.trim()).expect("bridge::start");
    // A conexao ocorre na thread; o protocolo precisa de tempo para SUBSCRIBE.
    thread::sleep(Duration::from_secs(2));
    publish_injected(port, ca, inject_pw.trim());
    let started = Instant::now();
    loop {
        if bus
            .received
            .lock()
            .expect("mutex")
            .iter()
            .any(|x| x == "alerts")
        {
            break;
        }
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "bridge nao repassou lab/alerts ao bus de teste"
        );
        thread::sleep(Duration::from_millis(100));
    }
    eprintln!("APROVADO BRI-LAB: bridge::start, TLS, autenticacao, SUBSCRIBE e entrada lab/alerts->bus de teste");
}
