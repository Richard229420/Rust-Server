//! Laboratorio BRI (port 8901): bridge::start real, bus adaptado, credenciais efemeras.
//! Ignorado por padrao; executar somente via controlador Python isolado.
use std::{
    env, fs,
    io::BufReader,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

mod messaging {
    use std::{
        fs::OpenOptions,
        io::{self, Write},
        sync::{mpsc::SyncSender, Mutex},
    };

    pub struct BridgeMessage {
        pub topic: String,
        pub body: String,
    }

    pub struct Bus {
        progress: std::path::PathBuf,
        sender: Mutex<Option<SyncSender<BridgeMessage>>>,
    }

    impl Bus {
        pub fn new(progress: std::path::PathBuf) -> Self {
            Self {
                progress,
                sender: Mutex::new(None),
            }
        }
        pub fn attach_bridge(&self, tx: SyncSender<BridgeMessage>) -> io::Result<()> {
            *self.sender.lock().expect("bus sender") = Some(tx);
            Ok(())
        }
        pub fn publish_from_mqtt(&self, topic: &str, body: &str) -> io::Result<()> {
            if topic == "alerts" && body.starts_with("BRI_TEST_") {
                let mut f = OpenOptions::new().append(true).open(&self.progress)?;
                writeln!(f, "{body}")?;
                f.flush()?;
            }
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

fn read_private(name: &str) -> String {
    fs::read_to_string(env::var(name).expect("secret file path missing"))
        .expect("secret file missing")
        .trim()
        .to_owned()
}

fn options(mode: &str) -> MqttOptions {
    let port: u16 = env::var("BRI_LAB_PORT")
        .expect("port")
        .parse()
        .expect("integer port");
    assert_eq!(port, 8901, "only isolated port 8901");
    let ca = env::var("BRI_LAB_CA").expect("ephemeral CA");
    let mut roots = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut BufReader::new(fs::File::open(&ca).expect("CA exists")))
    {
        roots.add(cert.expect("PEM cert")).expect("trusted CA");
    }
    let tls = ClientConfig::builder_with_provider(Arc::new(
        rumqttc::tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    let (username, password, client_id) = match mode {
        "publish" => (
            "injector",
            read_private("BRI_LAB_INJECTOR_PWFILE"),
            "bri-ciclo-injector",
        ),
        "accept" | "reject" => (
            "bridge",
            read_private("BRI_LAB_BRIDGE_PWFILE"),
            "bri-ciclo-probe",
        ),
        _ => panic!("unsupported client mode"),
    };
    let mut opts = MqttOptions::new(client_id, "localhost", port);
    opts.set_credentials(username, &password);
    opts.set_transport(Transport::tls_with_config(tls.into()));
    opts.set_keep_alive(Duration::from_secs(10));
    opts.set_clean_session(true);
    opts
}

fn client_mode(mode: &str) {
    let (client, mut connection) = Client::new(options(mode), 16);
    if mode == "publish" {
        let marker = env::var("BRI_LAB_MARKER").expect("stage marker");
        assert!(
            marker.starts_with("BRI_TEST_") && marker.len() <= 100,
            "marker invalid"
        );
        client
            .publish("lab/alerts", QoS::AtLeastOnce, false, marker.as_bytes())
            .expect("enqueue test publication");
        for notification in connection.iter() {
            match notification {
                Ok(Event::Incoming(Packet::PubAck(_))) => return,
                Err(_) => panic!("publication not acknowledged"),
                _ => {}
            }
        }
        panic!("event loop ended without PubAck");
    }
    match connection.iter().next() {
        Some(Ok(Event::Incoming(Packet::ConnAck(_)))) if mode == "accept" => {}
        Some(Err(_)) if mode == "reject" => {}
        _ => panic!("unexpected broker authentication response"),
    }
}

fn bridge_mode() {
    let port: u16 = env::var("BRI_LAB_PORT")
        .expect("port")
        .parse()
        .expect("integer port");
    assert_eq!(port, 8901, "only isolated port 8901");
    let progress = env::var("BRI_LAB_PROGRESS").expect("progress file");
    let ready = env::var("BRI_LAB_READY").expect("ready file");
    let stop = env::var("BRI_LAB_STOP").expect("stop file");
    let ca = env::var("BRI_LAB_CA").expect("CA");
    let password = read_private("BRI_LAB_BRIDGE_PWFILE");
    let bus = Arc::new(messaging::Bus::new(progress.into()));
    bridge::start(
        bus,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        Path::new(&ca),
        &password,
    )
    .expect("bridge::start");
    // Ready means threads created, NOT authenticated; publication validates real delivery.
    fs::write(ready, b"threads-created").expect("ready signal");
    let deadline = Instant::now() + Duration::from_secs(70);
    while Instant::now() < deadline {
        if Path::new(&stop).exists() {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("bridge test was not stopped by isolated controller");
}

#[test]
#[ignore = "only use the ephemeral BRI controller on port 8901"]
fn lifecycle_bri() {
    match env::var("BRI_LAB_MODE").expect("explicit mode").as_str() {
        "bridge" => bridge_mode(),
        "publish" => client_mode("publish"),
        "accept" => client_mode("accept"),
        "reject" => client_mode("reject"),
        _ => panic!("unexpected laboratory mode"),
    }
}
