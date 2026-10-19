//! Fase 6.4: quotas em memoria, limite de trabalho Argon2, auditoria sem segredos.
//! Nao confiar em X-Forwarded-For; usar endereco TCP real, obtido pelo servidor.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use rusqlite::{Connection, OpenFlags, params};

const WINDOW: Duration = Duration::from_secs(60);
const BLOCK: Duration = Duration::from_secs(60);
const MAX_ENTRIES: usize = 4096;
const MAX_HASHES: usize = 2;
const MAX_ACCOUNT_FAILURES: u32 = 5;
const MAX_SOURCE_FAILURES: u32 = 20;
const AUDIT_RETENTION_DAYS: i64 = 90;

static LIMITS: OnceLock<Mutex<HashMap<String, Attempt>>> = OnceLock::new();
static HASHES: AtomicUsize = AtomicUsize::new(0);
static LOGIN_OK: AtomicU64 = AtomicU64::new(0);
static LOGIN_FAIL: AtomicU64 = AtomicU64::new(0);
static LOGIN_LIMITED: AtomicU64 = AtomicU64::new(0);
static LOGIN_OVERLOAD: AtomicU64 = AtomicU64::new(0);
static RBAC_DENIED: AtomicU64 = AtomicU64::new(0);
static AUTH_REJECTED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
struct Attempt {
    since: Instant,
    failures: u32,
    blocked_until: Option<Instant>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AdmissionError {
    RateLimited,
    Busy,
}

// A guarda libera a vaga mesmo quando uma verificacao retorna erro/panico.
pub(super) struct Admission {
    account_key: String,
    source_key: String,
}

impl Drop for Admission {
    fn drop(&mut self) {
        HASHES.fetch_sub(1, Ordering::Release);
    }
}

fn limits() -> &'static Mutex<HashMap<String, Attempt>> {
    LIMITS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn refresh(attempt: &mut Attempt, now: Instant) {
    if now.duration_since(attempt.since) >= WINDOW
        && attempt.blocked_until.is_none_or(|until| now >= until)
    {
        *attempt = Attempt {
            since: now,
            failures: 0,
            blocked_until: None,
        };
    }
}

fn blocked(attempt: &mut Attempt, now: Instant) -> bool {
    refresh(attempt, now);
    attempt.blocked_until.is_some_and(|until| now < until)
}

fn try_reserve(slots: &AtomicUsize) -> bool {
    slots
        .try_update(Ordering::AcqRel, Ordering::Acquire, |in_flight| {
            (in_flight < MAX_HASHES).then_some(in_flight + 1)
        })
        .is_ok()
}

fn acquire_cpu() -> bool {
    try_reserve(&HASHES)
}

pub(super) fn admit(username: &str, peer_ip: &str) -> Result<Admission, AdmissionError> {
    // Username ja passou pela validacao ASCII 3-64 do handler de login.
    let account_key = format!("a:{}", username.to_ascii_lowercase());
    // peer_ip vem de TcpStream::peer_addr(), nunca de header HTTP nao confiavel.
    let source_key = format!("s:{peer_ip}");
    let now = Instant::now();
    let mut state = limits()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Prune de tentativas antigas; limite absoluto impede crescimento ilimitado de memoria.
    if state.len() >= MAX_ENTRIES {
        state.retain(|_, entry| {
            entry.blocked_until.is_some_and(|until| now < until)
                || now.duration_since(entry.since) < WINDOW
        });
    }
    let blocked_account = state
        .get_mut(&account_key)
        .is_some_and(|value| blocked(value, now));
    let blocked_source = state
        .get_mut(&source_key)
        .is_some_and(|value| blocked(value, now));
    let required = usize::from(!state.contains_key(&account_key))
        + usize::from(!state.contains_key(&source_key));
    if blocked_account || blocked_source || state.len() + required > MAX_ENTRIES {
        LOGIN_LIMITED.fetch_add(1, Ordering::Relaxed);
        return Err(AdmissionError::RateLimited);
    }
    // Mantem a chave por conta antes do Argon2 para limitar o tamanho mesmo sem falhas.
    state.entry(account_key.clone()).or_insert(Attempt {
        since: now,
        failures: 0,
        blocked_until: None,
    });
    state.entry(source_key.clone()).or_insert(Attempt {
        since: now,
        failures: 0,
        blocked_until: None,
    });
    drop(state);
    if !acquire_cpu() {
        LOGIN_OVERLOAD.fetch_add(1, Ordering::Relaxed);
        return Err(AdmissionError::Busy);
    }
    Ok(Admission {
        account_key,
        source_key,
    })
}

fn failure(state: &mut HashMap<String, Attempt>, key: &str, max_failures: u32, now: Instant) {
    if let Some(entry) = state.get_mut(key) {
        refresh(entry, now);
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= max_failures {
            entry.blocked_until = Some(now + BLOCK);
        }
    }
}

pub(super) fn finish(admission: &Admission, authenticated: bool) {
    let mut state = limits()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if authenticated {
        LOGIN_OK.fetch_add(1, Ordering::Relaxed);
        state.remove(&admission.account_key);
        // Nao limpar o limite por origem: isso permitiria contorna-lo com uma conta valida.
    } else {
        LOGIN_FAIL.fetch_add(1, Ordering::Relaxed);
        let now = Instant::now();
        failure(
            &mut state,
            &admission.account_key,
            MAX_ACCOUNT_FAILURES,
            now,
        );
        failure(&mut state, &admission.source_key, MAX_SOURCE_FAILURES, now);
    }
}

pub(super) fn audit(
    path: &std::path::Path,
    account_id: Option<i64>,
    event: &str,
    outcome: &str,
) -> Result<(), String> {
    // Eventos sao nomes estaticos do codigo; sem username, IP, token ou senha.
    if !matches!(
        event,
        "login_limited" | "login_overload" | "access_denied" | "auth_rejected"
    ) || !matches!(outcome, "denied" | "failure")
    {
        return Err("Evento de auditoria desconhecido".into());
    }
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    conn.busy_timeout(Duration::from_secs(2))
        .map_err(|e| e.to_string())?;
    conn.execute(
        "INSERT INTO auth_audit_events(account_id, event_type, outcome) VALUES (?1, ?2, ?3)",
        params![account_id, event, outcome],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

pub(super) fn note_denial(path: &std::path::Path, account_id: Option<i64>, forbidden: bool) {
    if forbidden {
        RBAC_DENIED.fetch_add(1, Ordering::Relaxed);
    } else {
        AUTH_REJECTED.fetch_add(1, Ordering::Relaxed);
    }
    // O acesso ja esta negado. Falha na escrita jamais transforma 401/403 em acesso permitido.
    let _ = audit(
        path,
        account_id,
        if forbidden {
            "access_denied"
        } else {
            "auth_rejected"
        },
        "denied",
    );
}

pub(super) fn prune(path: &std::path::Path) -> Result<usize, String> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| e.to_string())?;
    conn.busy_timeout(Duration::from_secs(3))
        .map_err(|e| e.to_string())?;
    conn.execute(
        "DELETE FROM auth_audit_events WHERE occurred_at < unixepoch() - ?1",
        [AUDIT_RETENTION_DAYS * 86400],
    )
    .map_err(|e| e.to_string())
}

pub(super) fn metrics() -> String {
    let counters = [
        (
            "rust_server_auth_login_success_total",
            LOGIN_OK.load(Ordering::Relaxed),
        ),
        (
            "rust_server_auth_login_failure_total",
            LOGIN_FAIL.load(Ordering::Relaxed),
        ),
        (
            "rust_server_auth_login_limited_total",
            LOGIN_LIMITED.load(Ordering::Relaxed),
        ),
        (
            "rust_server_auth_argon2_overload_total",
            LOGIN_OVERLOAD.load(Ordering::Relaxed),
        ),
        (
            "rust_server_auth_rbac_denied_total",
            RBAC_DENIED.load(Ordering::Relaxed),
        ),
        (
            "rust_server_auth_rejected_total",
            AUTH_REJECTED.load(Ordering::Relaxed),
        ),
    ];
    let mut lines = String::new();
    for (name, value) in counters {
        lines.push_str(&format!("# TYPE {name} counter\n{name} {value}\n"));
    }
    lines.push_str(&format!(
        "# TYPE rust_server_auth_argon2_inflight gauge\nrust_server_auth_argon2_inflight {}\n",
        HASHES.load(Ordering::Relaxed)
    ));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_block_after_five_failures_and_reset_on_window_expiry() {
        let seed = format!("test64_{}", std::process::id());
        for _ in 0..MAX_ACCOUNT_FAILURES {
            let admission = admit(&seed, "test64-peer").unwrap();
            finish(&admission, false);
            drop(admission);
        }
        assert!(matches!(
            admit(&seed, "test64-peer"),
            Err(AdmissionError::RateLimited)
        ));
        let account = format!("a:{}", seed.to_ascii_lowercase());
        let source = "s:test64-peer";
        let mut state = limits().lock().unwrap();
        for key in [account.as_str(), source] {
            let entry = state.get_mut(key).unwrap();
            entry.since = Instant::now() - WINDOW - Duration::from_secs(1);
            entry.blocked_until = Some(Instant::now() - Duration::from_secs(1));
        }
        drop(state);
        let admission = admit(&seed, "test64-peer").unwrap();
        finish(&admission, true);
    }

    #[test]
    fn source_limit_cannot_be_bypassed_with_different_usernames() {
        let origin = format!("source64_{}", std::process::id());
        for i in 0..MAX_SOURCE_FAILURES {
            let username = format!("candidate64_{i}_{}", std::process::id());
            let admission = admit(&username, &origin).unwrap();
            finish(&admission, false);
        }
        assert!(matches!(
            admit("anotheruser64", &origin),
            Err(AdmissionError::RateLimited)
        ));
    }

    #[test]
    fn argon2_semaphore_never_allows_more_than_two() {
        // Teste da primitiva atomica, nao usa credenciais reais.
        let local = AtomicUsize::new(0);
        assert!(try_reserve(&local));
        assert!(try_reserve(&local));
        assert!(!try_reserve(&local));
        assert_eq!(local.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn metrics_include_counters_without_labels_secretos() {
        let text = metrics();
        assert!(text.contains("rust_server_auth_login_limited_total"));
        assert!(!text.contains("username="));
    }
}
