#!/usr/bin/env python3
"""Refinamento da Fase 5: exercita persistencia SQLite apos reiniciar o Rust.

A porta 8080 deve estar LIVRE. Usa DB temporario independente dos dados reais.
Executar: python3 tests/sqlite_persistence.py
"""

import concurrent.futures
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from api_rest import http

ROOT = Path(__file__).resolve().parents[1]
HOST, PORT = "127.0.0.1", 8080
PROCESS = None


def port_open():
    try:
        with socket.create_connection((HOST, PORT), timeout=0.15):
            return True
    except OSError:
        return False


def start(db_path: Path):
    global PROCESS
    if port_open():
        raise RuntimeError("Porta 8080 ocupada. Encerre cargo run/Caddy backend antes do teste.")
    env = os.environ.copy()
    env["RUST_SERVER_DB_PATH"] = str(db_path)
    PROCESS = subprocess.Popen(
        [str(ROOT / "target/release/server")],
        cwd=ROOT, env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    for _ in range(80):
        if PROCESS.poll() is not None:
            error = PROCESS.stderr.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Rust encerrou ao iniciar: {error[-1200:]}")
        if port_open():
            return
        time.sleep(0.075)
    raise RuntimeError("Rust nao iniciou na porta 8080")


def stop():
    global PROCESS
    if PROCESS is None:
        return
    if PROCESS.poll() is None:
        PROCESS.terminate()
        try:
            PROCESS.wait(timeout=5)
        except subprocess.TimeoutExpired:
            PROCESS.kill()
            PROCESS.wait(timeout=5)
    PROCESS.stderr.close()
    PROCESS = None
    for _ in range(40):
        if not port_open():
            break
        time.sleep(0.05)


def expect(actual, expected, label):
    if actual != expected:
        raise AssertionError(f"{label}: esperado {expected!r}; recebido {actual!r}")
    print(f"[OK] {label}")


def main():
    if port_open():
        raise RuntimeError("Porta 8080 ocupada. Pare o servidor Rust antes de iniciar o teste.")
    print("[SQLITE] Compilando servidor release...")
    subprocess.run(["cargo", "build", "--release"], cwd=ROOT, check=True)
    token = uuid.uuid4().hex[:10]
    with tempfile.TemporaryDirectory(prefix="rust-fase5-sqlite-") as temp:
        db_path = Path(temp) / "users.sqlite3"
        try:
            start(db_path)
            created = http("POST", "/api/v1/users", {
                "name": "Persistente", "email": f"persist-{token}@example.com"
            })
            expect(created[0], 201, "POST cria usuario no SQLite")
            user_id = created[3]["data"]["id"]
            expect(created[1]["location"], [f"/api/v1/users/{user_id}"], "Location correta")
            stop()

            with sqlite3.connect(db_path) as con:
                expect(con.execute("PRAGMA user_version").fetchone()[0], 1, "Schema versionado")
                expect(con.execute("SELECT COUNT(*) FROM api_users").fetchone()[0], 1, "SQLite persistiu registro")
                expect(con.execute("PRAGMA journal_mode").fetchone()[0], "wal", "Journal WAL")

            start(db_path)
            found = http("GET", f"/api/v1/users/{user_id}", content_type=None)
            expect(found[0], 200, "GET apos reiniciar")
            expect(found[3]["data"]["name"], "Persistente", "Dados preservados")
            expect(http("POST", "/api/v1/users", {
                "name": "Duplicado", "email": f"PERSIST-{token}@EXAMPLE.COM"
            })[0], 409, "Unicidade de email apos restart")
            updated = http("PATCH", f"/api/v1/users/{user_id}", {"name": "Alterado"})
            expect(updated[0], 200, "PATCH persistido")
            stop()

            start(db_path)
            found = http("GET", f"/api/v1/users/{user_id}", content_type=None)
            expect(found[3]["data"]["name"], "Alterado", "PATCH sobreviveu ao restart")
            expect(http("DELETE", f"/api/v1/users/{user_id}", content_type=None)[0], 204, "DELETE persistido")
            stop()

            start(db_path)
            expect(http("GET", f"/api/v1/users/{user_id}", content_type=None)[0], 404, "DELETE sobreviveu ao restart")
            fresh = http("POST", "/api/v1/users", {
                "name": "Seguinte", "email": f"seguinte-{token}@example.com"
            })
            expect(fresh[0], 201, "Criacao apos exclusao")
            if fresh[3]["data"]["id"] <= user_id:
                raise AssertionError("ID SQLite foi reutilizado")
            print("[OK] AUTOINCREMENT manteve IDs monotonicos")

            def create_same(_):
                return http("POST", "/api/v1/users", {
                    "name": "Concorrente", "email": f"igual-{token}@example.com"
                })[0]
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                statuses = list(pool.map(create_same, range(8)))
            expect(statuses.count(201), 1, "Somente um POST concorrente com email igual")
            expect(statuses.count(409), 7, "Conflitos concorrentes corretamente rejeitados")
            stop()

            with sqlite3.connect(db_path) as con:
                expect(con.execute("PRAGMA integrity_check").fetchone()[0], "ok", "Integridade SQLite")

            # Banco de versao futura deve recusar iniciar e nunca ser reescrito.
            future = Path(temp) / "future.sqlite3"
            with sqlite3.connect(future) as con:
                con.execute("PRAGMA user_version = 99")
            env = os.environ.copy()
            env["RUST_SERVER_DB_PATH"] = str(future)
            result = subprocess.run(
                [str(ROOT / "target/release/server")], cwd=ROOT, env=env,
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 or "Versao SQLite nao suportada" not in result.stderr:
                raise AssertionError(f"Schema futuro nao foi recusado: {result.stderr[-500:]}")
            print("[OK] Versao de schema desconhecida bloqueia startup")
            print("[OK] Refinamento SQLite aprovado, sem alterar dados reais.")
        finally:
            stop()


if __name__ == "__main__":
    try:
        sys.exit(main() or 0)
    except (AssertionError, RuntimeError, OSError, subprocess.SubprocessError) as exc:
        print(f"[FALHOU] {exc}", file=sys.stderr)
        sys.exit(1)
