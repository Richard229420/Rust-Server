#!/usr/bin/env python3
"""Fase 6.1: testa banco de identidades, inicializacao segura e compatibilidade REST.

Executar na raiz do projeto com porta 8080 livre. Utiliza APENAS bancos temporarios.
"""
import os
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
HOST = '127.0.0.1'
PORT = 8080
APPLICATION_ID = 0x52535441


def port_open():
    try:
        with socket.create_connection((HOST, PORT), timeout=0.1):
            return True
    except OSError:
        return False


def env_for(users_db):
    env = os.environ.copy()
    env['RUST_SERVER_DB_PATH'] = str(users_db)
    env.pop('RUST_SERVER_AUTH_DB_PATH', None)
    return env


def start(users_db):
    proc = subprocess.Popen([str(ROOT / 'target/release/server')], cwd=ROOT,
                            env=env_for(users_db), stdout=subprocess.DEVNULL,
                            stderr=subprocess.PIPE)
    for _ in range(100):
        if proc.poll() is not None:
            error = proc.stderr.read().decode('utf-8', 'replace')
            raise AssertionError(f'Rust encerrou durante inicializacao: {error[-800:]}')
        if port_open():
            return proc
        time.sleep(0.05)
    stop(proc)
    raise AssertionError('Rust nao inicializou em ate 5s')


def stop(proc):
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if proc.stderr:
        proc.stderr.close()
    for _ in range(30):
        if not port_open():
            return
        time.sleep(0.05)


def expect(predicate, message):
    if not predicate:
        raise AssertionError(message)
    print(f'[OK] {message}')


def refusal(users_db, expected):
    env = env_for(users_db)
    try:
        proc = subprocess.run([str(ROOT / 'target/release/server')], cwd=ROOT,
                              env=env, capture_output=True, text=True, timeout=5)
    except subprocess.TimeoutExpired as exc:
        raise AssertionError('Servidor aceitou banco auth inseguro e permaneceu em execucao') from exc
    expect(proc.returncode != 0 and expected in proc.stderr,
           f'Startup recusa banco auth invalido: {expected}')
    expect(not port_open(), 'Nenhuma porta HTTP aberta apos falha do auth SQLite')


def main():
    expect(not port_open(), 'Porta 8080 livre antes do teste')
    subprocess.run(['cargo', 'build', '--release'], cwd=ROOT, check=True)
    with tempfile.TemporaryDirectory(prefix='rust-auth61-') as temp:
        root = Path(temp)
        users = root / 'users.sqlite3'
        auth = root / 'auth' / 'auth.sqlite3'
        proc = start(users)
        try:
            with urlopen(f'http://{HOST}:{PORT}/health', timeout=3) as response:
                expect(response.status == 200, 'Health HTTP preservado')
            with urlopen(f'http://{HOST}:{PORT}/api/v1/users', timeout=3) as response:
                expect(response.status == 200, 'API REST permanece compativel na Fase 6.1')
        finally:
            stop(proc)

        expect(users.is_file() and auth.is_file(), 'Bancos REST e auth separados')
        with sqlite3.connect(users) as con:
            expect(con.execute('PRAGMA user_version').fetchone()[0] == 1,
                   'Schema REST permanece na versao 1')
            expect('auth_accounts' not in [r[0] for r in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")],
                'REST nao ganhou tabelas de autenticacao')
        with sqlite3.connect(auth) as con:
            expect(con.execute('PRAGMA user_version').fetchone()[0] == 1,
                   'Schema de identidades versionado')
            expect(con.execute('PRAGMA application_id').fetchone()[0] == APPLICATION_ID,
                   'Identificador do banco de autenticacao correto')
            names = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            expect({'auth_accounts', 'auth_sessions', 'auth_audit_events'}.issubset(names),
                   'Tabelas auth preparadas para fases seguintes')
            expect(con.execute('SELECT count(*) FROM auth_accounts').fetchone()[0] == 0,
                   'Nenhum administrador ou credencial padrao criada')
            expect(con.execute('PRAGMA integrity_check').fetchone()[0] == 'ok',
                   'Integridade do auth SQLite')
        if os.name == 'posix':
            expect(stat.S_IMODE(auth.stat().st_mode) & 0o077 == 0,
                   'Arquivo SQLite de identidades privado (0600)')
            expect(stat.S_IMODE(auth.parent.stat().st_mode) & 0o077 == 0,
                   'Diretorio SQLite de identidades privado (0700)')

        proc = start(users)
        try:
            with urlopen(f'http://{HOST}:{PORT}/health', timeout=3) as response:
                expect(response.status == 200, 'Reinicio com schema auth valido')
        finally:
            stop(proc)

        with sqlite3.connect(auth) as con:
            con.execute('PRAGMA user_version = 99')
        refusal(users, 'Versao de autenticacao nao suportada')
        with sqlite3.connect(auth) as con:
            con.execute('PRAGMA user_version = 1')

        if os.name == 'posix':
            auth.chmod(0o644)
            refusal(users, 'Banco auth deve ser arquivo regular privado')
            auth.chmod(0o600)

    print('[OK] Fase 6.1: integracao SQLite e inicializacao aprovadas.')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, OSError, subprocess.SubprocessError, sqlite3.Error) as error:
        print(f'[FALHOU] {error}', file=sys.stderr)
        sys.exit(1)
