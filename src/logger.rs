use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub fn log_request(method: &str, path: &str, status: u16, duration: Duration) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    println!(
        "[{}] {} {} -> {} ({} ms)",
        timestamp,
        method,
        path,
        status,
        duration.as_millis()
    );
}

pub fn log_info(message: &str) {
    println!("[INFO] {message}");
}

pub fn log_error(message: &str) {
    eprintln!("[ERROR] {message}");
}
