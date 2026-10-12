use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn read_file(path: &Path) -> io::Result<Vec<u8>> {
    fs::read(path)
}

pub fn build_public_path(public_dir: &str, request_path: &str) -> Option<PathBuf> {
    let clean_path = request_path
        .split('?')
        .next()
        .unwrap_or(request_path)
        .trim_start_matches('/');

    if clean_path.is_empty() {
        return None;
    }

    let relative = Path::new(clean_path);

    // Impede caminhos como:
    //
    // /../../etc/passwd

    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return None;
    }

    Some(Path::new(public_dir).join(relative))
}
