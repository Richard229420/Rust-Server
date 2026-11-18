#!/usr/bin/env python3
"""Smoke isolado Fase 8.4: broker 8901 descartavel; sem tocar 8883/8884.

Nao modifica fontes Rust em src/. Exige teste Rust previamente instalado em tests/.
Sem acesso remoto; sem credenciais reais; nao registra C-V1 automaticamente.
"""
from __future__ import annotations

import os
import pathlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

PORT = 8901
ROOT = pathlib.Path(__file__).resolve().parents[1]
TEST = ROOT / "tests" / "bridge_fase8_4_bri_lab.rs"


def call(*args: str, cwd: pathlib.Path | None = None) -> None:
    subprocess.run(args, check=True, cwd=cwd, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=45)


def write_private(path: pathlib.Path, value: str) -> None:
    with path.open("x", encoding="utf-8") as f:
        f.write(value)
    path.chmod(0o600)


def preflight() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("nao execute como root")
    if not TEST.is_file() or TEST.is_symlink():
        raise RuntimeError("teste Rust isolado ausente ou inseguro")
    for command in ("cargo", "openssl", "mosquitto", "mosquitto_passwd"):
        if not shutil.which(command):
            raise RuntimeError(f"comando ausente: {command}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", PORT))
    print("APROVADO: requisitos encontrados; 127.0.0.1:8901 livre.", flush=True)


def make_pki(tmp: pathlib.Path) -> None:
    call("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
         "-subj", "/CN=Rust Bridge BRI Test CA", "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(tmp / "ca.key"),
         "-out", str(tmp / "ca.crt"))
    call("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-subj", "/CN=localhost", "-keyout", str(tmp / "server.key"),
         "-out", str(tmp / "server.csr"))
    write_private(tmp / "server.ext",
                  "basicConstraints=critical,CA:FALSE\n"
                  "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                  "extendedKeyUsage=serverAuth\n"
                  "keyUsage=digitalSignature,keyEncipherment\n")
    call("openssl", "x509", "-req", "-days", "1", "-sha256",
         "-in", str(tmp / "server.csr"), "-CA", str(tmp / "ca.crt"),
         "-CAkey", str(tmp / "ca.key"), "-CAcreateserial",
         "-extfile", str(tmp / "server.ext"), "-out", str(tmp / "server.crt"))
    for f in ("ca.key", "server.key"):
        (tmp / f).chmod(0o600)


def make_mosquitto_config(tmp: pathlib.Path) -> None:
    write_private(tmp / "bridge.pw", secrets.token_hex(24))
    write_private(tmp / "injector.pw", secrets.token_hex(24))
    write_private(tmp / "passwords", "bridge:" + (tmp / "bridge.pw").read_text() + "\n"
                  + "injector:" + (tmp / "injector.pw").read_text() + "\n")
    # -U transforma SOMENTE arquivo texto criado agora, exatamente uma vez.
    call("mosquitto_passwd", "-U", str(tmp / "passwords"))
    write_private(tmp / "acl", "user bridge\n"
                  "topic read lab/alerts\ntopic read lab/sensors/#\n"
                  "topic write bus/alerts\ntopic write bus/sensors/#\n"
                  "user injector\ntopic write lab/alerts\n")
    write_private(tmp / "mosquitto.conf", f"listener {PORT} 127.0.0.1\n"
                  "allow_anonymous false\npersistence false\n"
                  f"password_file {tmp / 'passwords'}\nacl_file {tmp / 'acl'}\n"
                  f"certfile {tmp / 'server.crt'}\nkeyfile {tmp / 'server.key'}\n"
                  f"log_dest file {tmp / 'broker.log'}\nlog_type error\nlog_type warning\n"
                  "log_type notice\n")


def wait_broker(p: subprocess.Popen[bytes]) -> None:
    for _ in range(50):
        if p.poll() is not None:
            raise RuntimeError("broker temporario terminou; revise log local privado")
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.15):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("broker temporario nao ficou acessivel em 8901")


def main() -> int:
    old_umask = os.umask(0o077)
    try:
        preflight()
        with tempfile.TemporaryDirectory(prefix="rust-bri-lab-") as t:
            tmp = pathlib.Path(t)
            tmp.chmod(0o700)
            make_pki(tmp)
            make_mosquitto_config(tmp)
            proc = None
            try:
                with (tmp / "mosquitto.stdout").open("wb") as out, (tmp / "mosquitto.stderr").open("wb") as err:
                    proc = subprocess.Popen(["mosquitto", "-c", str(tmp / "mosquitto.conf")],
                                            stdout=out, stderr=err, cwd=tmp)
                    wait_broker(proc)
                    print("APROVADO: Mosquitto descartavel TLS ativo em 127.0.0.1:8901.", flush=True)
                    env = os.environ.copy()
                    env.update({"BRI_LAB_PORT": str(PORT), "BRI_LAB_CA": str(tmp / "ca.crt"),
                                "BRI_LAB_BRIDGE_PWFILE": str(tmp / "bridge.pw"),
                                "BRI_LAB_INJECTOR_PWFILE": str(tmp / "injector.pw")})
                    # Teste #[ignore]: a suite cargo test normal nao abre broker.
                    result = subprocess.run(["cargo", "test", "--offline", "--locked", "--test",
                                             "bridge_fase8_4_bri_lab", "--", "--ignored", "--nocapture",
                                             "--test-threads=1"], cwd=ROOT, env=env,
                                            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                            timeout=90)
                    # Nao exibir stderr/saidas brutas: podem conter dados de ambiente.
                    if result.returncode != 0 or "1 passed" not in result.stdout:
                        raise RuntimeError("teste Rust falhou (saida omitida por seguranca); "
                                           "execute localmente com revisao antes de compartilhar")
                    print("APROVADO: bridge::start real conectou com TLS/autenticacao e recebeu lab/alerts.")
                    print("LIMITES: bus simulado; somente broker B; nao valida ACL negada, rotacao, rollback ou cenario A.")
                    print("C-V1: 21 abertas; nenhuma baixa; 8883 e 8884 intocados.")
                    return 0
            finally:
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as exc:
        print(f"BLOQUEADO: {type(exc).__name__}. Verifique localmente; nao exponha arquivos privados.",
              file=sys.stderr)
        sys.exit(2)
