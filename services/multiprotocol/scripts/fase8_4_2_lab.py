#!/usr/bin/env python3
"""Rust-Server 8.4.2: broker experimental em 127.0.0.1:8884 (SEM tocar no 8883)."""
from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path.home() / ".config/rust-server/phase8-4-2-lab"
PORT = 8884
BROKER_HOST = "127.0.0.1"
PLUGIN = Path("/usr/lib/mosquitto_dynamic_security.so")
ADMIN = "lab84-admin"
CLIENTS = {
    "device-sensor01": ("role-sensor01", "lab84-sensor01"),
    "device-sensor02": ("role-sensor02", "lab84-sensor02"),
    "lab84-bridge": ("role-bridge", "lab84-bridge"),
}


class Abort(Exception):
    pass


def must(condition: bool, message: str) -> None:
    if not condition:
        raise Abort(message)


def check_dir(path: Path) -> None:
    must(not path.is_symlink(), f"Diretorio nao pode ser symlink: {path}")
    must(path.is_dir() and path.stat().st_uid == os.getuid(), f"Diretorio ausente ou de outro usuario: {path}")
    must(not (path.stat().st_mode & 0o077), f"Diretorio nao e 0700: {path}")


def check_private(path: Path) -> None:
    must(not path.is_symlink(), f"Symlink proibido: {path}")
    must(path.is_file(), f"Arquivo ausente: {path}")
    info = path.stat()
    must(info.st_uid == os.getuid() and info.st_nlink == 1, f"Proprietario ou hardlink inseguro: {path}")
    must(not (info.st_mode & 0o077), f"Arquivo nao privado (0600): {path}")


def safe_write(path: Path, content: str) -> None:
    must(not path.exists() and not path.is_symlink(), f"Nao sobrescrever: {path}")
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(content)
    os.chmod(path, 0o600)


def command(args: list[str], *, input_text: str | None = None, timeout: int = 25) -> str:
    result = subprocess.run(args, text=True, input=input_text, capture_output=True, timeout=timeout, check=False)
    output = result.stdout + result.stderr
    if result.returncode != 0 or "Error:" in output or "error:" in output:
        # Podem conter nomes de contas, mas nunca exibir senhas ou argumentos secretos.
        raise Abort(f"Falha na operacao: {args[0]} {args[-1]} (codigo {result.returncode}); verifique log local")
    return output


def port_open(port: int) -> bool:
    try:
        with socket.create_connection((BROKER_HOST, port), timeout=0.35):
            return True
    except (OSError, TimeoutError):
        return False


def preflight() -> None:
    must(os.geteuid() != 0, "Execute como usuario normal, nunca sudo/root")
    for program in ("mosquitto", "mosquitto_ctrl", "mosquitto_pub", "mosquitto_sub", "openssl"):
        must(shutil.which(program) is not None, f"Comando nao encontrado: {program}")
    must(PLUGIN.is_file(), f"Plugin ausente: {PLUGIN}")
    must(not port_open(PORT), f"Porta {PORT} ja ocupada. Nao sobrescreva outro broker")


def init_dirs() -> None:
    cfg = ROOT.parent
    must(cfg.is_dir(), f"Diretorio de configuracoes ausente: {cfg}")
    # Diretório 8.3 é propriedade de outro processo? Nunca alterar.
    check_dir(cfg)
    must(not ROOT.exists() and not ROOT.is_symlink(), f"Laboratorio existente: {ROOT}; nao sobrescrever")
    ROOT.mkdir(mode=0o700)
    for sub in ("pki", "clients"):
        (ROOT / sub).mkdir(mode=0o700)


def prepare() -> None:
    preflight()
    pw = getpass.getpass(f"Defina uma senha FORTE exclusiva para {ADMIN} (sem espacos): ")
    must(len(pw) >= 20 and not any(c.isspace() for c in pw),
         "Senha precisa ter 20+ caracteres e nao conter espacos")
    confirmation = getpass.getpass("Repita a senha administrativa: ")
    must(secrets.compare_digest(pw, confirmation), "Senhas nao conferem")
    init_dirs()
    pki = ROOT / "pki"
    # CA e certificado de servidor EXCLUSIVOS do laboratorio (nao reutilizam a CA da 8.3).
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes", "-days", "30",
             "-subj", "/CN=Rust-Server MQTT Lab CA 8.4.2", "-keyout", str(pki / "ca.key"),
             "-out", str(pki / "ca.crt")])
    command(["openssl", "req", "-new", "-newkey", "rsa:2048", "-sha256", "-nodes",
             "-subj", "/CN=localhost", "-keyout", str(pki / "server.key"),
             "-out", str(pki / "server.csr")])
    safe_write(pki / "san.cnf", "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n")
    command(["openssl", "x509", "-req", "-in", str(pki / "server.csr"), "-CA", str(pki / "ca.crt"),
             "-CAkey", str(pki / "ca.key"), "-CAcreateserial", "-out", str(pki / "server.crt"),
             "-days", "30", "-sha256", "-extfile", str(pki / "san.cnf")])
    for entry in pki.iterdir():
        if entry.is_file():
            os.chmod(entry, 0o600)
    conf = "\n".join([
        "# Laboratorio Rust-Server 8.4.2, separado do broker principal 8883",
        "persistence false",
        "log_dest stdout",
        "connection_messages true",
        "max_packet_size 8192",
        "max_inflight_messages 16",
        f"plugin_load labdynsec {PLUGIN}",
        f"plugin_opt_config_file {ROOT / 'dynamic-security.json'}",
        "",
        f"listener {PORT} {BROKER_HOST}",
        "listener_allow_anonymous false",
        f"certfile {pki / 'server.crt'}",
        f"keyfile {pki / 'server.key'}",
        f"cafile {pki / 'ca.crt'}",
        "tls_version tlsv1.2",
        "plugin_use labdynsec",
        "",
    ])
    safe_write(ROOT / "mosquitto-lab.conf", conf)
    # Senha transmitida apenas por stdin, nao via argv, shell history ou arquivo.
    command(["mosquitto_ctrl", "dynsec", "init", str(ROOT / "dynamic-security.json"), ADMIN],
            input_text=f"{pw}\n{pw}\n")
    os.chmod(ROOT / "dynamic-security.json", 0o600)
    check_private(ROOT / "dynamic-security.json")
    print(f"APROVADO: laboratorio criado em {ROOT} (somente arquivos locais e TLS de teste).")
    print("NEXT: em outro terminal execute 'python3 scripts/fase8_4_2_lab.py iniciar'; depois '... provisionar'.")
    print("IMPORTANTE: anote a senha administrativa em um gerenciador de senhas; ela nao foi salva.")


def validated_root() -> None:
    check_dir(ROOT.parent)
    check_dir(ROOT)
    check_dir(ROOT / "clients")
    check_dir(ROOT / "pki")
    for name in ("mosquitto-lab.conf", "dynamic-security.json", "pki/ca.crt", "pki/server.crt", "pki/server.key"):
        check_private(ROOT / name)
    config = (ROOT / "mosquitto-lab.conf").read_text()
    must(f"listener {PORT} {BROKER_HOST}" in config, "Configuracao nao e local/8884")
    must("listener_allow_anonymous false" in config and "plugin_use labdynsec" in config, "Configuracao insegura")
    must(str(ROOT / "dynamic-security.json") in config, "Estado do plugin nao e local")


def start() -> None:
    validated_root()
    must(not port_open(PORT), "Porta 8884 ja ocupada: nao iniciar segunda instancia")
    print("BROKER LAB 8.4.2: somente 127.0.0.1:8884. Pressione Ctrl+C para parar.", flush=True)
    os.execvp("mosquitto", ["mosquitto", "-c", str(ROOT / "mosquitto-lab.conf"), "-v"])


def secure_client_options(username: str, client_id: str, password: str) -> str:
    return (f"-h localhost\n-p {PORT}\n--cafile {ROOT / 'pki/ca.crt'}\n"
            f"-u {username}\n-P {password}\n-i {client_id}\n")


def invoke_control(ctrl_opts: Path, *args: str, input_text: str | None = None) -> None:
    cmd = ["mosquitto_ctrl", "-o", str(ctrl_opts), "dynsec", *args]
    command(cmd, input_text=input_text)


def provision() -> None:
    validated_root()
    must(port_open(PORT), "Inicie o broker de laboratorio 8884 antes de provisionar")
    must(not (ROOT / "provisioned.json").exists(), "Laboratorio ja provisionado: nao duplicar contas")
    must(not list((ROOT / "clients").iterdir()), "Contas parciais: investigue antes de repetir")
    admin_pw = getpass.getpass(f"Senha administrativa de {ADMIN} (somente nesta execucao): ")
    must(len(admin_pw) >= 20 and not any(c.isspace() for c in admin_pw),
         "Senha administrativa invalida (20+ caracteres, sem espacos)")
    with tempfile.TemporaryDirectory(prefix=".admin-session-", dir=ROOT) as temp:
        os.chmod(temp, 0o700)
        opts = Path(temp) / "ctrl.opts"
        safe_write(opts, secure_client_options(ADMIN, "lab84-admin-setup", admin_pw))
        invoke_control(opts, "getDefaultACLAccess")  # confirma autenticacao real
        for category in ("publishClientSend", "publishClientReceive", "subscribe", "unsubscribe"):
            invoke_control(opts, "setDefaultACLAccess", category, "deny")
        roles = {
            "role-sensor01": [
                ("publishClientSend", "lab/sensors/sensor01/#"),
                ("publishClientReceive", "bus/sensors/sensor01/#"),
                ("subscribePattern", "bus/sensors/sensor01/#"),
            ],
            "role-sensor02": [
                ("publishClientSend", "lab/sensors/sensor02/#"),
                ("publishClientReceive", "bus/sensors/sensor02/#"),
                ("subscribePattern", "bus/sensors/sensor02/#"),
            ],
            "role-bridge": [
                ("publishClientSend", "bus/sensors/#"),
                ("publishClientReceive", "lab/sensors/#"),
                ("subscribePattern", "lab/sensors/#"),
            ],
        }
        for role, policies in roles.items():
            invoke_control(opts, "createRole", role)
            for kind, topic in policies:
                invoke_control(opts, "addRoleACL", role, kind, topic, "allow", "10")
        # Senhas geradas em RAM, fornecidas ao mosquitto_ctrl APENAS via stdin.
        for username, (role, client_id) in CLIENTS.items():
            password = secrets.token_hex(32)
            invoke_control(opts, "createClient", username, input_text=f"{password}\n{password}\n")
            invoke_control(opts, "setClientId", username, client_id)
            invoke_control(opts, "addClientRole", username, role, "10")
            safe_write(ROOT / "clients" / (username + ".opts"), secure_client_options(username, client_id, password))
        safe_write(ROOT / "provisioned.json", json.dumps({"phase": "8.4.2", "port": PORT, "clients": list(CLIENTS)}, indent=2))
    print("APROVADO: contas e ACLs provisionadas no broker 8884; permissoes padrao DENY.")
    print("Credenciais exclusivas em ~/.config/rust-server/phase8-4-2-lab/clients/*.opts (0600; NAO commitar).")
    print("NEXT: python3 scripts/test_fase8_4_2_isolamento.py")


def status() -> None:
    validated_root()
    print("PORTA 8884:", "LISTEN" if port_open(PORT) else "OFFLINE")
    print("PORTA 8883:", "LISTEN" if port_open(8883) else "OFFLINE (broker existente nao foi modificado)")
    print("CLIENTES LAB:", "configurados" if (ROOT / "provisioned.json").is_file() else "pendentes")
    print("RAIZ LAB:", ROOT)


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["preparar", "iniciar", "provisionar", "status"])
    args = parser.parse_args()
    try:
        {"preparar": prepare, "iniciar": start, "provisionar": provision, "status": status}[args.action]()
    except (Abort, subprocess.TimeoutExpired, OSError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
