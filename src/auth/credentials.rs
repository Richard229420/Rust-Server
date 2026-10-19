//! Argon2id PHC para senhas; tokens opacos de 256 bits e digest SHA-256 no banco.
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

pub(super) const PASSWORD_MIN: usize = 12;
pub(super) const PASSWORD_MAX: usize = 128;

fn hasher() -> Argon2<'static> {
    // OWASP baseline Argon2id: 19 MiB, 2 iteracoes, paralelismo 1.
    let params = Params::new(19 * 1024, 2, 1, None).expect("parametros Argon2id fixos");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

pub(super) fn username_valid(name: &str) -> bool {
    (3..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

pub(super) fn hash_password(password: &str) -> Result<String, String> {
    if !(PASSWORD_MIN..=PASSWORD_MAX).contains(&password.len()) {
        return Err(format!(
            "A senha deve ter entre {PASSWORD_MIN} e {PASSWORD_MAX} bytes"
        ));
    }
    let salt = SaltString::generate(&mut OsRng);
    hasher()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("Falha Argon2id: {e}"))
}

pub(super) fn verify_password(password: &str, phc: &str) -> bool {
    PasswordHash::new(phc).ok().is_some_and(|parsed| {
        hasher()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

pub(super) fn spend_dummy_hash(password: &str) {
    // Resposta a usuario inexistente nao deve dispensar a operacao cara de hash.
    let salt = SaltString::generate(&mut OsRng);
    let _ = hasher().hash_password(password.as_bytes(), &salt);
}

pub(super) fn issue_token() -> (String, [u8; 32]) {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let mut token = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}").expect("String aceita write");
    }
    let digest = digest_token(&token);
    (token, digest)
}

pub(super) fn digest_token(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

pub(super) fn valid_token_format(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_is_random_and_verifiable() {
        let a = hash_password("senha-para-testes-12345").unwrap();
        let b = hash_password("senha-para-testes-12345").unwrap();
        assert_ne!(a, b);
        assert!(a.starts_with("$argon2id$v=19$"));
        assert!(verify_password("senha-para-testes-12345", &a));
        assert!(!verify_password("senha-incorreta-12345", &a));
    }

    #[test]
    fn token_is_random_and_has_fixed_digest() {
        let (a, digest_a) = issue_token();
        let (b, digest_b) = issue_token();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert_ne!(digest_a, digest_b);
        assert_eq!(digest_a, digest_token(&a));
        assert!(valid_token_format(&a));
        assert!(!valid_token_format("senha"));
    }

    #[test]
    fn username_and_password_limits() {
        assert!(username_valid("Admin_01"));
        assert!(!username_valid("admin @local"));
        assert!(hash_password("curta").is_err());
    }
}
