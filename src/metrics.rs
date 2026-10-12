//! Metrica HTTP com atomicos, sem dependencias externas.
//! Os contadores sao por processo e reiniciam ao reiniciar o servidor.

use std::array;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const STATUS_CODES: [u16; 9] = [200, 400, 403, 404, 405, 408, 413, 500, 503];
const BUCKETS_US: [u64; 8] = [
    1_000, 5_000, 10_000, 50_000, 100_000, 1_000_000, 5_000_000, 15_000_000,
];
const BUCKET_LABELS: [&str; 8] = ["0.001", "0.005", "0.01", "0.05", "0.1", "1", "5", "15"];

pub struct Metrics {
    started: Instant,
    connections_accepted: AtomicU64,
    workers_active: AtomicUsize,
    workers_peak: AtomicUsize,
    queue_depth: AtomicUsize,
    queue_peak: AtomicUsize,
    overload_rejected: AtomicU64,
    read_timeouts: AtomicU64,
    total_timeouts: AtomicU64,
    response_counts: [AtomicU64; 10],
    duration_sum_us: AtomicU64,
    duration_buckets: [AtomicU64; 8],
}

impl Metrics {
    pub fn new() -> Self {
        Self {
            started: Instant::now(),
            connections_accepted: AtomicU64::new(0),
            workers_active: AtomicUsize::new(0),
            workers_peak: AtomicUsize::new(0),
            queue_depth: AtomicUsize::new(0),
            queue_peak: AtomicUsize::new(0),
            overload_rejected: AtomicU64::new(0),
            read_timeouts: AtomicU64::new(0),
            total_timeouts: AtomicU64::new(0),
            response_counts: array::from_fn(|_| AtomicU64::new(0)),
            duration_sum_us: AtomicU64::new(0),
            duration_buckets: array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    pub fn accept(&self) {
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn enqueue(&self) {
        let depth = self.queue_depth.fetch_add(1, Ordering::Relaxed) + 1;
        self.queue_peak
            .fetch_max(depth.min(super::QUEUE_CAPACITY), Ordering::Relaxed);
    }

    pub fn dequeue(&self) {
        self.queue_depth.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn worker_start(&self) {
        let active = self.workers_active.fetch_add(1, Ordering::Relaxed) + 1;
        self.workers_peak.fetch_max(active, Ordering::Relaxed);
    }

    pub fn worker_end(&self) {
        self.workers_active.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn reject_overload(&self) {
        self.overload_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn timeout(&self, total: bool) {
        if total {
            self.total_timeouts.fetch_add(1, Ordering::Relaxed);
        } else {
            self.read_timeouts.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn respond(&self, status: u16, elapsed: Duration) {
        let index = STATUS_CODES.iter().position(|s| *s == status).unwrap_or(9);
        self.response_counts[index].fetch_add(1, Ordering::Relaxed);
        let us = elapsed.as_micros().min(u64::MAX as u128) as u64;
        self.duration_sum_us.fetch_add(us, Ordering::Relaxed);
        for (bucket, threshold) in self.duration_buckets.iter().zip(BUCKETS_US) {
            if us <= threshold {
                bucket.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub fn render(&self) -> String {
        let mut out = String::with_capacity(2800);
        let _ = writeln!(
            out,
            "# HELP rust_http_uptime_seconds Segundos desde o inicio do processo."
        );
        let _ = writeln!(out, "# TYPE rust_http_uptime_seconds gauge");
        let _ = writeln!(
            out,
            "rust_http_uptime_seconds {:.3}",
            self.started.elapsed().as_secs_f64()
        );
        for (name, kind, explanation, value) in [
            (
                "rust_http_connections_accepted_total",
                "counter",
                "Conexoes TCP aceitas.",
                self.connections_accepted.load(Ordering::Relaxed) as u64,
            ),
            (
                "rust_http_workers_active",
                "gauge",
                "Workers em processamento.",
                self.workers_active.load(Ordering::Relaxed) as u64,
            ),
            (
                "rust_http_workers_peak",
                "gauge",
                "Pico de workers ativos.",
                self.workers_peak.load(Ordering::Relaxed) as u64,
            ),
            (
                "rust_http_queue_depth",
                "gauge",
                "Conexoes aguardando na fila.",
                self.queue_depth.load(Ordering::Relaxed) as u64,
            ),
            (
                "rust_http_queue_peak",
                "gauge",
                "Maior tamanho observado da fila.",
                self.queue_peak.load(Ordering::Relaxed) as u64,
            ),
            (
                "rust_http_overload_rejected_total",
                "counter",
                "Conexoes rejeitadas por fila lotada.",
                self.overload_rejected.load(Ordering::Relaxed),
            ),
            (
                "rust_http_read_timeouts_total",
                "counter",
                "Timeouts por inatividade na leitura.",
                self.read_timeouts.load(Ordering::Relaxed),
            ),
            (
                "rust_http_deadline_timeouts_total",
                "counter",
                "Timeouts por prazo total de requisicao.",
                self.total_timeouts.load(Ordering::Relaxed),
            ),
        ] {
            let _ = writeln!(out, "# HELP {name} {explanation}");
            let _ = writeln!(out, "# TYPE {name} {kind}");
            let _ = writeln!(out, "{name} {value}");
        }
        let _ = writeln!(
            out,
            "# HELP rust_http_responses_total Respostas HTTP enviadas com sucesso por status."
        );
        let _ = writeln!(out, "# TYPE rust_http_responses_total counter");
        for (status, count) in STATUS_CODES.iter().zip(self.response_counts.iter()) {
            let _ = writeln!(
                out,
                "rust_http_responses_total{{status=\"{status}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        let _ = writeln!(
            out,
            "rust_http_responses_total{{status=\"other\"}} {}",
            self.response_counts[9].load(Ordering::Relaxed)
        );
        let _ = writeln!(
            out,
            "# HELP rust_http_response_duration_seconds Tempo desde a aceitacao da conexao ate o envio da resposta."
        );
        let _ = writeln!(out, "# TYPE rust_http_response_duration_seconds histogram");
        for (label, count) in BUCKET_LABELS.iter().zip(self.duration_buckets.iter()) {
            let _ = writeln!(
                out,
                "rust_http_response_duration_seconds_bucket{{le=\"{label}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        let count: u64 = self
            .response_counts
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        let _ = writeln!(
            out,
            "rust_http_response_duration_seconds_bucket{{le=\"+Inf\"}} {count}"
        );
        let sum = self.duration_sum_us.load(Ordering::Relaxed) as f64 / 1_000_000.0;
        let _ = writeln!(out, "rust_http_response_duration_seconds_sum {sum:.6}");
        let _ = writeln!(out, "rust_http_response_duration_seconds_count {count}");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::Metrics;
    use std::time::Duration;

    #[test]
    fn counts_responses_and_timing() {
        let m = Metrics::new();
        m.accept();
        m.enqueue();
        m.dequeue();
        m.worker_start();
        m.worker_end();
        m.respond(200, Duration::from_millis(2));
        m.timeout(false);
        let text = m.render();
        assert!(text.contains("rust_http_connections_accepted_total 1"));
        assert!(text.contains("rust_http_queue_depth 0"));
        assert!(text.contains("rust_http_workers_active 0"));
        assert!(text.contains("rust_http_responses_total{status=\"200\"} 1"));
        assert!(text.contains("rust_http_response_duration_seconds_count 1"));
        assert!(text.contains("rust_http_read_timeouts_total 1"));
    }
}
