//! Provisionamento local, nunca exposto em rotas HTTP.
#[allow(dead_code)]
#[path = "../auth.rs"]
mod auth;

use std::io::{self, Read};

fn password(from_stdin: bool) -> Result<String, String> {
    if from_stdin {
        let mut s = String::new();
        io::stdin()
            .take(256)
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
        return Ok(s.trim_end_matches(['\n', '\r']).to_string());
    }
    let first = rpassword::prompt_password("Senha nova (oculta): ").map_err(|e| e.to_string())?;
    let second =
        rpassword::prompt_password("Confirmar senha (oculta): ").map_err(|e| e.to_string())?;
    if first != second {
        return Err("As senhas digitadas sao diferentes".into());
    }
    Ok(first)
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 || args.len() > 3 {
        return Err("Uso: cargo run --bin auth_admin -- bootstrap|reset-password USUARIO [--password-stdin]".into());
    }
    let stdin = args.len() == 3 && args[2] == "--password-stdin";
    if args.len() == 3 && !stdin {
        return Err("Argumento desconhecido. Nunca passe a senha pela linha de comando".into());
    }
    if args[0] != "bootstrap" && args[0] != "reset-password" {
        return Err("Acao invalida: bootstrap ou reset-password".into());
    }
    // Nunca criar um banco novo de forma silenciosa com o utilitario de administracao.
    let path = auth::database_file();
    if !path.is_file() {
        return Err(format!(
            "Inicialize primeiro o servidor para criar o banco de auth: {}",
            path.display()
        ));
    }
    let pass = password(stdin)?;
    match args[0].as_str() {
        "bootstrap" => auth::bootstrap_admin(&args[1], &pass)?,
        "reset-password" => auth::reset_account_password(&args[1], &pass)?,
        _ => unreachable!(),
    }
    println!("[OK] Operacao local concluida. Nenhuma senha ou token exibido.");
    Ok(())
}

fn main() {
    if let Err(message) = run() {
        eprintln!("[ERRO] {message}");
        std::process::exit(1);
    }
}
