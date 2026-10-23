//! Protocolo proprio de mensageria para laboratorio (nao e MQTT/NATS/AMQP).
//! TCP/TLS: AUTH <token>, SUB <topico>, PUB <topico> <mensagem>, PING, QUIT.
//! UDP legado (DESATIVADO): PUB <token> <topico> <mensagem> (datagrama ate 4096 bytes).

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;

const MAX_CLIENTS: usize = 64;
const MAX_TOPICS: usize = 128;
const MAX_SUBSCRIBERS_PER_TOPIC: usize = 64;
const MAX_SUBSCRIPTIONS_PER_CLIENT: usize = 16;
const MAX_LINE: usize = 4096;
const MAX_MESSAGE: usize = 2048;
const READ_TIMEOUT: Duration = Duration::from_millis(250);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_COMMANDS_PER_SECOND: u32 = 30;

type Subscriber = mpsc::SyncSender<String>;
static NEXT_CLIENT_ID: AtomicU64 = AtomicU64::new(1);

pub struct Bus {
    subscribers: Mutex<HashMap<String, HashMap<u64, Subscriber>>>,
    bridge_tx: Mutex<Option<mpsc::SyncSender<BridgeMessage>>>,
    bridge_dropped: AtomicU64,
    token: String,
    read_token: String,
    write_token: String,
    rejected_auth: AtomicU64,
    rejected_acl: AtomicU64,
    rejected_limits: AtomicU64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BridgeMessage {
    pub topic: String,
    pub body: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum QueueResult {
    Disabled,
    Queued,
    Dropped,
}

#[derive(Debug, PartialEq, Eq)]
pub struct PublishResult {
    pub recipients: usize,
    pub mqtt: QueueResult,
}

impl PublishResult {
    fn ack(&self) -> String {
        if self.mqtt == QueueResult::Dropped {
            format!("OK PUB {} BRIDGE_DROPPED\n", self.recipients)
        } else {
            format!("OK PUB {}\n", self.recipients)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Admin,
    Reader,
    Writer,
}

fn secret_eq(expected: &str, candidate: &str) -> bool {
    expected.as_bytes().ct_eq(candidate.as_bytes()).into()
}

pub(crate) fn bridge_topic_allowed(topic: &str) -> bool {
    valid_topic(topic) && (topic == "alerts" || topic.starts_with("sensors/"))
}

fn permitted(role: Role, action: &str, topic: &str) -> bool {
    if !valid_topic(topic) {
        return false;
    }
    match role {
        Role::Admin => true,
        Role::Reader => action == "SUB" && bridge_topic_allowed(topic),
        Role::Writer => action == "PUB" && bridge_topic_allowed(topic),
    }
}

impl Bus {
    #[cfg(test)]
    pub fn new(token: String) -> Self {
        Self::with_roles(
            token,
            "unused-reader-token".into(),
            "unused-writer-token".into(),
        )
    }

    pub fn with_roles(token: String, read_token: String, write_token: String) -> Self {
        Self {
            subscribers: Mutex::new(HashMap::new()),
            bridge_tx: Mutex::new(None),
            bridge_dropped: AtomicU64::new(0),
            token,
            read_token,
            write_token,
            rejected_auth: AtomicU64::new(0),
            rejected_acl: AtomicU64::new(0),
            rejected_limits: AtomicU64::new(0),
        }
    }

    fn authorized(&self, candidate: &str) -> bool {
        secret_eq(&self.token, candidate)
    }

    fn role(&self, candidate: &str) -> Option<Role> {
        if secret_eq(&self.token, candidate) {
            Some(Role::Admin)
        } else if secret_eq(&self.read_token, candidate) {
            Some(Role::Reader)
        } else if secret_eq(&self.write_token, candidate) {
            Some(Role::Writer)
        } else {
            None
        }
    }

    fn audit_denial(&self, kind: &'static str) {
        let counter = match kind {
            "auth" => &self.rejected_auth,
            "acl" => &self.rejected_acl,
            _ => &self.rejected_limits,
        };
        let total = counter.fetch_add(1, Ordering::Relaxed) + 1;
        if total == 1 || total % 100 == 0 {
            eprintln!("[AUDIT] mensagem rejeitada: {kind}, total={total} (sem credenciais no log)");
        }
    }

    // Uma inscricao por conexao e topico; evita alocacao ilimitada com SUB repetido.
    fn subscribe(
        &self,
        topic: &str,
        connection_id: u64,
        sender: Subscriber,
    ) -> Result<(), &'static str> {
        if !valid_topic(topic) {
            return Err("topico invalido");
        }
        let mut map = self.subscribers.lock().map_err(|_| "bus indisponivel")?;
        if !map.contains_key(topic) && map.len() >= MAX_TOPICS {
            map.retain(|_, subscribers| !subscribers.is_empty());
            if map.len() >= MAX_TOPICS {
                return Err("limite de topicos atingido");
            }
        }
        let subscribers = map.entry(topic.to_owned()).or_default();
        if subscribers.contains_key(&connection_id) {
            return Ok(());
        }
        if subscribers.len() >= MAX_SUBSCRIBERS_PER_TOPIC {
            return Err("limite de assinantes do topico");
        }
        subscribers.insert(connection_id, sender);
        Ok(())
    }

    fn unsubscribe_client(&self, connection_id: u64) {
        if let Ok(mut map) = self.subscribers.lock() {
            map.retain(|_, subscribers| {
                subscribers.remove(&connection_id);
                !subscribers.is_empty()
            });
        }
    }

    // Executado apenas uma vez durante a inicializacao, antes dos listeners.
    pub fn attach_bridge(&self, sender: mpsc::SyncSender<BridgeMessage>) -> io::Result<()> {
        let mut guard = self
            .bridge_tx
            .lock()
            .map_err(|_| io::Error::other("mutex bridge indisponivel"))?;
        if guard.is_some() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "bridge ja iniciada",
            ));
        }
        *guard = Some(sender);
        Ok(())
    }

    pub fn publish(&self, topic: &str, body: &str) -> Result<PublishResult, &'static str> {
        self.publish_internal(topic, body, true)
    }

    // O broker MQTT publica no bus local, mas a mensagem nao retorna ao broker.
    pub fn publish_from_mqtt(
        &self,
        topic: &str,
        body: &str,
    ) -> Result<PublishResult, &'static str> {
        self.publish_internal(topic, body, false)
    }

    fn publish_internal(
        &self,
        topic: &str,
        body: &str,
        to_mqtt: bool,
    ) -> Result<PublishResult, &'static str> {
        if !valid_topic(topic) || !valid_body(body) {
            return Err("mensagem ou topico invalido");
        }
        let recipients = {
            let mut map = self.subscribers.lock().map_err(|_| "bus indisponivel")?;
            if let Some(subscribers) = map.get_mut(topic) {
                let payload = format!("MSG {topic} {body}\n");
                subscribers.retain(|_, subscriber| subscriber.try_send(payload.clone()).is_ok());
                let delivered = subscribers.len();
                if delivered == 0 {
                    map.remove(topic);
                }
                delivered
            } else {
                0
            }
        };
        // Fora do lock da lista de assinantes. O envio para MQTT nunca bloqueia
        // e nem permite que a fila cresca sem limite.
        let mqtt = if !to_mqtt {
            QueueResult::Disabled
        } else {
            let guard = self.bridge_tx.lock().map_err(|_| "bridge indisponivel")?;
            match guard.as_ref() {
                None => QueueResult::Disabled,
                Some(sender) => match sender.try_send(BridgeMessage {
                    topic: topic.to_owned(),
                    body: body.to_owned(),
                }) {
                    Ok(()) => QueueResult::Queued,
                    Err(_) => {
                        let dropped = self.bridge_dropped.fetch_add(1, Ordering::Relaxed) + 1;
                        if dropped == 1 || dropped % 100 == 0 {
                            eprintln!("[BRIDGE] fila de saida MQTT indisponivel/cheia: {dropped} descarte(s)");
                        }
                        QueueResult::Dropped
                    }
                },
            }
        };
        Ok(PublishResult { recipients, mqtt })
    }
}

pub(crate) fn valid_topic(topic: &str) -> bool {
    !topic.is_empty()
        && topic.len() <= 64
        && !topic.starts_with('/')
        && !topic.ends_with('/')
        && !topic.contains("//")
        && topic
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'/'))
}

pub(crate) fn valid_body(body: &str) -> bool {
    !body.is_empty() && body.len() <= MAX_MESSAGE && !body.chars().any(char::is_control)
}

pub fn tcp_listener(addr: SocketAddr, bus: Arc<Bus>, tls: Arc<ServerConfig>) -> io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    let active = Arc::new(AtomicUsize::new(0));
    let mut denied_connections: u64 = 0;
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
                    active.fetch_sub(1, Ordering::SeqCst);
                    denied_connections += 1;
                    if denied_connections == 1 || denied_connections % 100 == 0 {
                        eprintln!(
                            "[AUDIT] limite TCP atingido; conexoes recusadas={denied_connections}"
                        );
                    }
                    // Resposta plaintext proibida na porta TLS.
                    drop(stream);
                    continue;
                }
                let bus = Arc::clone(&bus);
                let active_worker = Arc::clone(&active);
                let tls_worker = Arc::clone(&tls);
                match thread::Builder::new()
                    .name("bus-tls-client".into())
                    .spawn(move || {
                        let _count_guard = ClientGuard(active_worker);
                        if let Err(err) = handle_tls(stream, bus, tls_worker) {
                            eprintln!("[TCP-TLS] conexao encerrada: {err}");
                        }
                    }) {
                    Ok(_) => {}
                    Err(err) => {
                        active.fetch_sub(1, Ordering::SeqCst);
                        eprintln!("[TCP] erro ao criar thread: {err}");
                        return Err(err);
                    }
                }
            }
            Err(err) => eprintln!("[TCP] accept: {err}"),
        }
    }
    Ok(())
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

struct SubscriptionGuard {
    bus: Arc<Bus>,
    connection_id: u64,
}
impl Drop for SubscriptionGuard {
    fn drop(&mut self) {
        self.bus.unsubscribe_client(self.connection_id);
    }
}

struct ClientGuard(Arc<AtomicUsize>);
impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn handle_tls(socket: TcpStream, bus: Arc<Bus>, tls: Arc<ServerConfig>) -> io::Result<()> {
    socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    socket.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let conn = ServerConnection::new(tls).map_err(io::Error::other)?;
    let mut stream = StreamOwned::new(conn, socket);
    // Handshake antes de enviar qualquer frame ou credencial.
    stream.conn.complete_io(&mut stream.sock)?;
    stream.sock.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.sock.set_write_timeout(Some(WRITE_TIMEOUT))?;

    // Fecha a sessao TLS de maneira ordenada depois de um termino
    // normal do protocolo (por exemplo, apos "BYE" no comando QUIT).
    // Descartar StreamOwned sem close_notify provoca UnexpectedEof
    // nos clientes rustls, mesmo quando receberam o ACK da publicacao.
    let result = handle_tcp(&mut stream, bus);
    if result.is_ok() {
        stream.conn.send_close_notify();
        stream.flush()?;
    }
    result
}

fn handle_tcp(stream: &mut impl ReadWrite, bus: Arc<Bus>) -> io::Result<()> {
    stream.write_all(b"HELLO rust-server-bus/1\nAUTH <token> para continuar\n")?;
    let (tx, rx) = mpsc::sync_channel::<String>(64);
    let connection_id = NEXT_CLIENT_ID.fetch_add(1, Ordering::Relaxed);
    let _cleanup = SubscriptionGuard {
        bus: Arc::clone(&bus),
        connection_id,
    };
    let mut active_topics = HashSet::<String>::new();
    let mut role: Option<Role> = None;
    let connected_at = Instant::now();
    let mut rate_window = Instant::now();
    let mut commands_in_window = 0_u32;
    let mut pending = Vec::with_capacity(1024);
    let mut block = [0_u8; 1024];
    loop {
        if role.is_none() && connected_at.elapsed() > Duration::from_secs(5) {
            stream.write_all(b"ERR prazo autenticacao\n")?;
            return Ok(());
        }
        while let Ok(msg) = rx.try_recv() {
            stream.write_all(msg.as_bytes())?;
        }
        match stream.read(&mut block) {
            Ok(0) => return Ok(()),
            Ok(n) => {
                pending.extend_from_slice(&block[..n]);
                if pending.len() > MAX_LINE && !pending.contains(&b'\n') {
                    stream.write_all(b"ERR linha muito longa\n")?;
                    return Ok(());
                }
                while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                    if end >= MAX_LINE {
                        stream.write_all(b"ERR linha muito longa\n")?;
                        return Ok(());
                    }
                    let line = pending.drain(..=end).collect::<Vec<u8>>();
                    let line = match std::str::from_utf8(&line) {
                        Ok(value) => value.trim_end_matches(&['\r', '\n'][..]),
                        Err(_) => {
                            stream.write_all(b"ERR UTF-8 invalido\n")?;
                            return Ok(());
                        }
                    };
                    if rate_window.elapsed() >= Duration::from_secs(1) {
                        rate_window = Instant::now();
                        commands_in_window = 0;
                    }
                    commands_in_window += 1;
                    if commands_in_window > MAX_COMMANDS_PER_SECOND {
                        bus.audit_denial("limite_comandos");
                        stream.write_all(b"ERR limite comandos\n")?;
                        return Ok(());
                    }
                    if role.is_none() {
                        match line
                            .strip_prefix("AUTH ")
                            .and_then(|candidate| bus.role(candidate))
                        {
                            Some(granted) => {
                                role = Some(granted);
                                stream.write_all(b"OK AUTH\n")?;
                            }
                            None => {
                                bus.audit_denial("auth");
                                stream.write_all(b"ERR autenticacao\n")?;
                                return Ok(());
                            }
                        }
                        continue;
                    }
                    if line == "PING" {
                        stream.write_all(b"PONG\n")?;
                    } else if line == "QUIT" {
                        stream.write_all(b"BYE\n")?;
                        return Ok(());
                    } else if let Some(topic) = line.strip_prefix("SUB ") {
                        if !permitted(role.expect("autenticado"), "SUB", topic) {
                            bus.audit_denial("acl");
                            stream.write_all(b"ERR acesso negado\n")?;
                            continue;
                        }
                        if !active_topics.contains(topic)
                            && active_topics.len() >= MAX_SUBSCRIPTIONS_PER_CLIENT
                        {
                            bus.audit_denial("limite_assinaturas");
                            stream.write_all(b"ERR limite assinaturas\n")?;
                            continue;
                        }
                        match bus.subscribe(topic, connection_id, tx.clone()) {
                            Ok(()) => {
                                active_topics.insert(topic.to_owned());
                                stream.write_all(b"OK SUB\n")?;
                            }
                            Err("limite de assinantes do topico") => {
                                bus.audit_denial("limite_assinantes_topico");
                                stream.write_all(b"ERR limite assinantes\n")?;
                            }
                            Err(_) => stream.write_all(b"ERR topico\n")?,
                        }
                    } else if let Some(data) = line.strip_prefix("PUB ") {
                        if let Some((topic, body)) = data.split_once(' ') {
                            if !permitted(role.expect("autenticado"), "PUB", topic) {
                                bus.audit_denial("acl");
                                stream.write_all(b"ERR acesso negado\n")?;
                                continue;
                            }
                            match bus.publish(topic, body) {
                                Ok(report) => stream.write_all(report.ack().as_bytes())?,
                                Err(_) => stream.write_all(b"ERR mensagem\n")?,
                            }
                        } else {
                            stream.write_all(b"ERR sintaxe\n")?;
                        }
                    } else {
                        stream.write_all(b"ERR comando\n")?;
                    }
                }
                if pending.len() > MAX_LINE {
                    stream.write_all(b"ERR linha muito longa\n")?;
                    return Ok(());
                }
            }
            Err(ref err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            Err(err) => return Err(err),
        }
    }
}

pub fn udp_listener(addr: SocketAddr, bus: Arc<Bus>) -> io::Result<()> {
    let socket = UdpSocket::bind(addr)?;
    let mut bytes = [0_u8; MAX_LINE + 1];
    loop {
        let (n, peer) = socket.recv_from(&mut bytes)?;
        if n == 0 || n > MAX_LINE {
            continue;
        }
        let Ok(data) = std::str::from_utf8(&bytes[..n]) else {
            continue;
        };
        // UDP nao garante ordem, entrega ou nao duplicacao de datagramas.
        let reply = match data.strip_prefix("PUB ") {
            Some(content) => {
                let mut fields = content.splitn(3, ' ');
                match (fields.next(), fields.next(), fields.next()) {
                    (Some(token), Some(topic), Some(body)) if bus.authorized(token) => {
                        match bus.publish(topic, body) {
                            Ok(report) => report.ack(),
                            Err(_) => "ERR mensagem\n".to_owned(),
                        }
                    }
                    _ => "ERR autenticacao ou sintaxe\n".to_owned(),
                }
            }
            None => "ERR comando\n".to_owned(),
        };
        let _ = socket.send_to(reply.as_bytes(), peer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topicos_e_mensagens_validos() {
        assert!(valid_topic("lab/temperatura"));
        assert!(!valid_topic("a/#"));
        assert!(!valid_topic("../admin".repeat(15).as_str()));
        assert!(!valid_body("ola\nmundo"));
    }

    #[test]
    fn autenticacao_e_pubsub() {
        let bus = Bus::new("token-local-super-seguro".into());
        assert!(bus.authorized("token-local-super-seguro"));
        assert!(!bus.authorized("token-local-errado"));
        let (tx, rx) = mpsc::sync_channel(2);
        bus.subscribe("alerts", 1, tx).unwrap();
        assert_eq!(
            bus.publish("alerts", "sistema online").unwrap().recipients,
            1
        );
        assert_eq!(rx.try_recv().unwrap(), "MSG alerts sistema online\n");
        assert_eq!(
            bus.publish("outro", "sem assinantes").unwrap().recipients,
            0
        );
    }

    #[test]
    fn eventos_mqtt_nao_retornam_para_mqtt() {
        let bus = Bus::new("token-local-super-seguro".into());
        let (bridge_tx, bridge_rx) = mpsc::sync_channel(4);
        bus.attach_bridge(bridge_tx).unwrap();
        let (tx, rx) = mpsc::sync_channel(4);
        bus.subscribe("alerts", 1, tx).unwrap();
        let result = bus.publish_from_mqtt("alerts", "mensagem MQTT").unwrap();
        assert_eq!(result.recipients, 1);
        assert_eq!(result.mqtt, QueueResult::Disabled);
        assert_eq!(rx.try_recv().unwrap(), "MSG alerts mensagem MQTT\n");
        assert!(bridge_rx.try_recv().is_err());
        let result = bus.publish("alerts", "mensagem TCP").unwrap();
        assert_eq!(result.mqtt, QueueResult::Queued);
        let forwarded = bridge_rx.try_recv().unwrap();
        assert_eq!(forwarded.topic, "alerts");
        assert_eq!(forwarded.body, "mensagem TCP");
    }

    #[test]
    fn papeis_e_acl_por_topico() {
        let bus = Bus::with_roles("A".repeat(48), "B".repeat(48), "C".repeat(48));
        assert_eq!(bus.role(&"A".repeat(48)), Some(Role::Admin));
        assert_eq!(bus.role(&"B".repeat(48)), Some(Role::Reader));
        assert_eq!(bus.role(&"C".repeat(48)), Some(Role::Writer));
        assert!(bus.role("invalid").is_none());
        assert!(permitted(Role::Reader, "SUB", "alerts"));
        assert!(!permitted(Role::Reader, "PUB", "alerts"));
        assert!(permitted(Role::Writer, "PUB", "sensors/temp"));
        assert!(!permitted(Role::Writer, "SUB", "alerts"));
        assert!(!permitted(Role::Writer, "PUB", "admin/secret"));
        assert!(permitted(Role::Admin, "PUB", "admin/secret"));
    }

    #[test]
    fn fila_saturada_nao_bloqueia_publicacao_local() {
        let bus = Bus::new("token-local-super-seguro".into());
        let (bridge_tx, _rx) = mpsc::sync_channel(1);
        bus.attach_bridge(bridge_tx).unwrap();
        let (tx, rx) = mpsc::sync_channel(4);
        bus.subscribe("alerts", 1, tx).unwrap();
        assert_eq!(
            bus.publish("alerts", "primeira").unwrap().mqtt,
            QueueResult::Queued
        );
        let result = bus.publish("alerts", "segunda").unwrap();
        assert_eq!(result.recipients, 1);
        assert_eq!(result.mqtt, QueueResult::Dropped);
        assert_eq!(result.ack(), "OK PUB 1 BRIDGE_DROPPED\n");
        assert_eq!(rx.try_recv().unwrap(), "MSG alerts primeira\n");
        assert_eq!(rx.try_recv().unwrap(), "MSG alerts segunda\n");
    }

    // Exercita a maquina de estados real do protocolo, sem depender de portas TLS.
    struct MemoryStream {
        input: std::io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl MemoryStream {
        fn new(commands: String) -> Self {
            Self {
                input: std::io::Cursor::new(commands.into_bytes()),
                output: Vec::new(),
            }
        }
        fn text(&self) -> String {
            String::from_utf8(self.output.clone()).unwrap()
        }
    }
    impl Read for MemoryStream {
        fn read(&mut self, dest: &mut [u8]) -> io::Result<usize> {
            self.input.read(dest)
        }
    }
    impl Write for MemoryStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    fn test_bus() -> Arc<Bus> {
        Arc::new(Bus::with_roles(
            "A".repeat(48),
            "B".repeat(48),
            "C".repeat(48),
        ))
    }
    fn protocol(bus: Arc<Bus>, commands: String) -> String {
        let mut stream = MemoryStream::new(commands);
        handle_tcp(&mut stream, bus).unwrap();
        stream.text()
    }
    #[test]
    fn nega_credenciais_incorretas_e_operacoes_nao_autorizadas() {
        let bus = test_bus();
        let wrong = protocol(Arc::clone(&bus), "AUTH errada\nPUB alerts nao\n".into());
        assert!(wrong.contains("ERR autenticacao"));
        assert!(!wrong.contains("OK PUB"));
        let denied_pub = protocol(
            Arc::clone(&bus),
            format!("AUTH {}\nPUB alerts negado\nQUIT\n", "B".repeat(48)),
        );
        assert!(denied_pub.contains("ERR acesso negado"));
        assert!(!denied_pub.contains("OK PUB"));
        let denied_sub = protocol(
            Arc::clone(&bus),
            format!("AUTH {}\nSUB alerts\nQUIT\n", "C".repeat(48)),
        );
        assert!(denied_sub.contains("ERR acesso negado"));
        assert!(!denied_sub.contains("OK SUB"));
        let denied_topic = protocol(
            bus,
            format!("AUTH {}\nPUB admin/secret negado\nQUIT\n", "C".repeat(48)),
        );
        assert!(denied_topic.contains("ERR acesso negado"));
    }

    #[test]
    fn sub_repetido_nao_consume_memoria_e_desconexao_remove_assinaturas() {
        let bus = test_bus();
        let mut commands = format!("AUTH {}\n", "B".repeat(48));
        for _ in 0..20 {
            commands.push_str("SUB alerts\n");
        }
        commands.push_str("QUIT\n");
        let output = protocol(Arc::clone(&bus), commands);
        assert_eq!(output.matches("OK SUB").count(), 20);
        assert!(!output.contains("ERR limite assinaturas"));
        assert!(bus.subscribers.lock().unwrap().is_empty());
    }

    #[test]
    fn limita_assinaturas_por_cliente_e_rejeita_excesso_de_comandos() {
        let bus = test_bus();
        let mut commands = format!("AUTH {}\n", "B".repeat(48));
        for n in 0..18 {
            commands.push_str(&format!("SUB sensors/t{n}\n"));
        }
        commands.push_str("QUIT\n");
        let output = protocol(Arc::clone(&bus), commands);
        assert_eq!(
            output.matches("OK SUB").count(),
            MAX_SUBSCRIPTIONS_PER_CLIENT
        );
        assert_eq!(output.matches("ERR limite assinaturas").count(), 2);
        assert!(bus.subscribers.lock().unwrap().is_empty());

        let flood = format!("AUTH {}\n{}", "C".repeat(48), "PING\n".repeat(45));
        let output = protocol(bus, flood);
        assert!(output.contains("ERR limite comandos"));
    }

    #[test]
    fn limita_numero_de_assinantes_por_topico() {
        let bus = test_bus();
        let mut receivers = Vec::new();
        for client in 1..=MAX_SUBSCRIBERS_PER_TOPIC as u64 {
            let (tx, rx) = mpsc::sync_channel(2);
            bus.subscribe("alerts", client, tx).unwrap();
            receivers.push(rx);
        }
        let (tx, _rx) = mpsc::sync_channel(2);
        assert_eq!(
            bus.subscribe("alerts", 9999, tx).unwrap_err(),
            "limite de assinantes do topico"
        );
        bus.unsubscribe_client(1);
        let (tx, rx) = mpsc::sync_channel(2);
        assert!(bus.subscribe("alerts", 9999, tx).is_ok());
        receivers.push(rx);
        assert_eq!(
            bus.subscribers.lock().unwrap().get("alerts").unwrap().len(),
            MAX_SUBSCRIBERS_PER_TOPIC
        );
    }
}
