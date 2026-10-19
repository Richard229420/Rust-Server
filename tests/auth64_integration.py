#!/usr/bin/env python3
"""Fase 6.4: login, auditoria, limites e retencao, apenas SQLite temporario."""
from __future__ import annotations
import concurrent.futures
import threading
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HOST, PORT = '127.0.0.1', 8080
SERVER = ROOT / 'target/release/server'
ADMIN = ROOT / 'target/release/auth_admin'
PASSWORD = 'senha-dedicada-temporaria-64'


def ok(valid, message):
    if not valid:
        raise AssertionError(message)
    print('[OK]', message)


def port_open():
    try:
        with socket.create_connection((HOST, PORT), timeout=.15):
            return True
    except OSError:
        return False


def call(method, path, payload=None, token=None):
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {'Host': 'localhost'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    if token is not None:
        headers['Authorization'] = 'Bearer ' + token
    connection = http.client.HTTPConnection(HOST, PORT, timeout=15)
    try:
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        try:
            content = json.loads(raw) if raw else None
        except (UnicodeError, ValueError):
            content = raw.decode('utf8', errors='replace')
        return response.status, dict(response.getheaders()), content
    finally:
        connection.close()


def boot(env):
    proc = subprocess.Popen([str(SERVER)], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(180):
        if proc.poll() is not None:
            raise AssertionError('Servidor encerrou: ' + proc.stderr.read().decode(errors='replace')[-1600:])
        if port_open():
            return proc
        time.sleep(.05)
    stop(proc)
    raise AssertionError('Servidor nao abriu porta 8080')


def stop(proc):
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    if proc.stderr:
        proc.stderr.close()
    for _ in range(40):
        if not port_open():
            return
        time.sleep(.05)


def main():
    ok(not port_open(), 'Porta 8080 livre: servidor real nao sera interrompido')
    ok(SERVER.is_file() and ADMIN.is_file(), 'Executaveis release presentes')
    with tempfile.TemporaryDirectory(prefix='rust-auth64-') as root:
        folder = Path(root)
        users = folder / 'users.sqlite3'
        auth = folder / 'auth' / 'auth.sqlite3'
        env = os.environ.copy()
        env['RUST_SERVER_DB_PATH'] = str(users)
        env['RUST_SERVER_AUTH_DB_PATH'] = str(auth)
        proc = None
        try:
            proc = boot(env)
            status, _, _ = call('GET', '/health')
            ok(status == 200, 'Health preservado')
            status, _, metrics = call('GET', '/internal/security-metrics')
            ok(status == 200 and 'rust_server_auth_login_failure_total' in metrics,
               'Metricas Prometheus de seguranca apenas locais')
            status, _, _ = call('GET', '/api/v1/users')
            ok(status == 401, 'RBAC continua exigindo token')
            stop(proc)
            proc = None
            created = subprocess.run([str(ADMIN), 'bootstrap', 'fixture64', '--password-stdin'],
                                     input=PASSWORD+'\n', text=True, cwd=ROOT, env=env,
                                     capture_output=True, timeout=25)
            ok(created.returncode == 0, 'Bootstrap realizado somente em banco temporario')
            with sqlite3.connect(auth) as db:
                hashed, = db.execute('SELECT password_hash FROM auth_accounts WHERE username=?',
                                     ('fixture64',)).fetchone()
                db.execute('INSERT INTO auth_accounts(username, password_hash, role) VALUES (?,?,?)',
                           ('reader64', hashed, 'viewer'))
                db.execute("INSERT INTO auth_audit_events(event_type,outcome,occurred_at) VALUES('old_fixture','success',unixepoch()-? )",
                           (100*86400,))
            proc = boot(env)
            with sqlite3.connect(auth) as db:
                ok(db.execute("SELECT count(*) FROM auth_audit_events WHERE event_type='old_fixture'").fetchone()[0] == 0,
                   'Eventos de auditoria com mais de 90 dias removidos no startup')
            status, _, payload = call('POST', '/api/v1/auth/login', {'username':'reader64', 'password':PASSWORD})
            ok(status == 200 and len(payload['access_token']) == 64, 'Login da conta viewer funciona')
            viewer_token = payload['access_token']
            status, _, _ = call('POST', '/api/v1/users', {'name':'Not Allowed','email':'na@lab.test'}, viewer_token)
            ok(status == 403, 'RBAC 403 permanece ativo')
            status, _, _ = call('GET', '/api/v1/users', token=viewer_token)
            ok(status == 200, 'Leitura permitida ao viewer')
            with sqlite3.connect(auth) as db:
                ok(db.execute("SELECT count(*) FROM auth_audit_events WHERE event_type='access_denied' AND outcome='denied'").fetchone()[0] >= 1,
                   'Negativa RBAC registrada sem identidade em texto puro')
            # 6 logins validos simultaneos exercitam o teto de 2 hashes Argon2id.
            barrier = threading.Barrier(6)
            def concurrent_login(_):
                barrier.wait(timeout=8)
                status, _, _ = call('POST', '/api/v1/auth/login',
                                    {'username':'reader64', 'password':PASSWORD})
                return status
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as workers:
                statuses = list(workers.map(concurrent_login, range(6)))
            ok(set(statuses).issubset({200, 429}) and 429 in statuses,
               'Concorrencia Argon2 limitada: logins excedentes recebem 429')

            bad = {'username':'fixture64', 'password':'incorrect_password_64'}
            for i in range(5):
                status, _, _ = call('POST', '/api/v1/auth/login', bad)
                ok(status == 401, f'Senha incorreta {i+1}/5 rejeitada')
            status, headers, payload = call('POST', '/api/v1/auth/login',
                                            {'username':'fixture64', 'password':PASSWORD})
            ok(status == 429 and headers.get('Retry-After') == '60' and payload['error']['code'] == 'rate_limited',
               'Sexta tentativa bloqueada antes do Argon2id, inclusive com senha correta')
            with sqlite3.connect(auth) as db:
                events = db.execute('SELECT event_type, outcome FROM auth_audit_events').fetchall()
                ok(('login_limited', 'denied') in events, '429 registrado em auditoria SQLite')
                ok(all('incorrect_password_64' not in str(event) for event in events),
                   'Auditoria nao contem senhas de teste')
            status, _, metrics = call('GET', '/internal/security-metrics')
            ok(status == 200 and 'rust_server_auth_login_limited_total 1' in metrics,
               'Contador de 429 incrementado')
            stop(proc)
            proc = None
            proc = boot(env)
            status, _, payload = call('POST', '/api/v1/auth/login',
                                      {'username':'fixture64', 'password':PASSWORD})
            ok(status == 200, 'Limites volateis reiniciados; credencial e conta persistiram')
            status, _, _ = call('GET', '/api/v1/auth/me', token=payload['access_token'])
            ok(status == 200, 'Nova sessao autentica corretamente')
            status, _, _ = call('POST', '/api/v1/auth/logout', token=payload['access_token'])
            ok(status == 204, 'Logout continua revogando token')
            status, _, _ = call('GET', '/api/v1/auth/me', token=payload['access_token'])
            ok(status == 401, 'Token revogado ainda rejeitado')
            ok(users.is_file() and auth.is_file(), 'SQLite REST e auth separados')
        finally:
            stop(proc)
    print('[OK] Fase 6.4: auditoria, quotas, metricas e regressao basica aprovadas em SQLite temporario')

if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('[FALHOU]', error, file=sys.stderr)
        sys.exit(1)
