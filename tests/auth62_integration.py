#!/usr/bin/env python3
"""Teste end-to-end fase 6.2: usa SOMENTE bancos temporarios. Porta 8080 livre."""
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
PASSWORD = 'senha-temporaria-integration-62'
NEW_PASSWORD = 'senha-temporaria-rotacionada-62'


def ok(value, description):
    if not value:
        raise AssertionError(description)
    print('[OK]', description)


def port_open():
    try:
        with socket.create_connection((HOST, PORT), timeout=.1):
            return True
    except OSError:
        return False


def request(method, url, json_body=None, token=None, raw=None, content_type='application/json'):
    headers = {'Host': 'localhost'}
    if token is not None:
        headers['Authorization'] = f'Bearer {token}'
    if json_body is not None:
        headers['Content-Type'] = content_type
        raw = json.dumps(json_body).encode()
    conn = http.client.HTTPConnection(HOST, PORT, timeout=5)
    try:
        conn.request(method, url, body=raw, headers=headers)
        response = conn.getresponse()
        data = response.read()
        headers = dict(response.getheaders())

        if not data:
            payload = None
        else:
            try:
                payload = json.loads(data)
            except (json.JSONDecodeError, UnicodeDecodeError):
                payload = data.decode("utf-8", errors="replace")

        return response.status, headers, payload
    finally:
        conn.close()


def boot(env):
    process = subprocess.Popen([str(SERVER)], cwd=ROOT, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(120):
        if process.poll() is not None:
            error = process.stderr.read().decode(errors='replace')
            raise AssertionError(f'Servidor encerrou durante inicializacao: {error[-1500:]}')
        if port_open():
            return process
        time.sleep(.05)
    stop(process)
    raise AssertionError('Servidor nao iniciou em 6 segundos')


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


def cli(env, mode, password):
    return subprocess.run([str(ADMIN), mode, 'testadmin', '--password-stdin'],
                          input=password + '\n', env=env, cwd=ROOT,
                          capture_output=True, text=True, timeout=15)


def main():
    ok(not port_open(), 'Porta 8080 esta livre')
    ok(SERVER.is_file() and ADMIN.is_file(), 'Binarios release estao presentes')
    with tempfile.TemporaryDirectory(prefix='rust-auth62-') as temp:
        directory = Path(temp)
        auth_db = directory / 'auth' / 'auth.sqlite3'
        env = os.environ.copy()
        env['RUST_SERVER_DB_PATH'] = str(directory / 'users.sqlite3')
        env['RUST_SERVER_AUTH_DB_PATH'] = str(auth_db)
        process = None
        try:
            process = boot(env)
            status, _, _ = request('GET', '/health')
            ok(status == 200, 'Health continua funcionando')
            status, _, _ = request('GET', '/api/v1/users')
            ok(status == 200, 'CRUD antigo preservado (RBAC ficara na 6.3)')
            status, _, _ = request('GET', '/api/v1/auth/me')
            ok(status == 401, 'ME exige Bearer')
            stop(process)
            process = None

            ok(auth_db.is_file(), 'Banco auth temporario foi criado')
            created = cli(env, 'bootstrap', PASSWORD)
            ok(created.returncode == 0, f'Bootstrap local aprovou administrador: {created.stderr[-200:]}')
            duplicate = cli(env, 'bootstrap', PASSWORD)
            ok(duplicate.returncode != 0, 'Bootstrap nao permite outro administrador')
            with sqlite3.connect(auth_db) as db:
                stored, role = db.execute('SELECT password_hash, role FROM auth_accounts').fetchone()
                ok(stored.startswith('$argon2id$') and PASSWORD not in stored and role == 'admin',
                   'SQLite armazena somente Argon2id, sem senha em claro')
                ok(db.execute('SELECT count(*) FROM auth_sessions').fetchone()[0] == 0,
                   'Nenhuma sessao preconfigurada')

            process = boot(env)
            status, headers, _ = request('POST', '/api/v1/auth/login',
                                         {'username': 'testadmin', 'password': 'senha-errada-12345'})
            ok(status == 401 and 'WWW-Authenticate' in headers, 'Senha incorreta retorna 401 sem revelar conta')
            status, _, _ = request('POST', '/api/v1/auth/login',
                                   {'username': 'inexistente', 'password': PASSWORD})
            ok(status == 401, 'Conta inexistente retorna 401')
            status, _, _ = request('POST', '/api/v1/auth/login', {'username': 'testadmin'})
            ok(status == 400, 'Payload incompleto rejeitado')
            status, headers, _ = request('GET', '/api/v1/auth/login')
            ok(status == 405 and headers.get('Allow') == 'POST', 'Metodos incorretos retornam 405 e Allow')
            status, _, _ = request('POST', '/api/v1/auth/login',
                                   {'username': 'testadmin', 'password': PASSWORD},
                                   content_type='text/plain')
            ok(status == 415, 'Login exige Content-Type application/json')
            status, _, data = request('POST', '/api/v1/auth/login',
                                      {'username': 'TESTADMIN', 'password': PASSWORD})
            ok(status == 200 and data['token_type'] == 'Bearer'
               and data['expires_in'] == 3600 and len(data['access_token']) == 64,
               'Login gera Bearer token 256 bits e 1h de validade')
            ok(headers.get('Cache-Control') == 'no-store', 'Login envia Cache-Control: no-store')
            token = data['access_token']
            status, _, profile = request('GET', '/api/v1/auth/me', token=token)
            ok(status == 200 and profile['role'] == 'admin'
               and profile['username'] == 'testadmin', 'ME devolve identidade real')
            status, _, _ = request('GET', '/api/v1/auth/me', token='0' * 64)
            ok(status == 401, 'Token falso rejeitado')
            status, _, _ = request('GET', '/api/v1/auth/me', token=token, raw=b'not allowed')
            ok(status == 400, 'ME nao aceita body')
            with sqlite3.connect(auth_db) as db:
                ok(db.execute('SELECT length(token_digest) FROM auth_sessions').fetchone()[0] == 32,
                   'Somente digest SHA256 (32 bytes) armazenado')
                ok(db.execute('SELECT hex(token_digest) FROM auth_sessions').fetchone()[0].lower() != token,
                   'Token nao armazenado em texto')
                events = db.execute('SELECT event_type, outcome FROM auth_audit_events').fetchall()
                ok(('login', 'failure') in events and ('login', 'success') in events,
                   'Auditoria basica registra sucessos e falhas sem segredos')

            stop(process)
            process = boot(env)
            status, _, _ = request('GET', '/api/v1/auth/me', token=token)
            ok(status == 200, 'Sessao persiste apos restart')
            status, _, body = request('POST', '/api/v1/auth/logout', token=token)
            ok(status == 204 and body is None, 'Logout retorna 204 sem body')
            status, _, _ = request('GET', '/api/v1/auth/me', token=token)
            ok(status == 401, 'Token revogado rejeitado')
            status, _, _ = request('POST', '/api/v1/auth/logout', token=token)
            ok(status == 401, 'Segundo logout rejeitado')
            status, _, data = request('POST', '/api/v1/auth/login',
                                      {'username': 'testadmin', 'password': PASSWORD})
            ok(status == 200, 'Novo login apos logout permitido')
            expiring = data['access_token']
            with sqlite3.connect(auth_db) as db:
                db.execute('UPDATE auth_sessions SET created_at = unixepoch() - 3600, expires_at = unixepoch() - 1 WHERE revoked_at IS NULL')
            status, _, _ = request('GET', '/api/v1/auth/me', token=expiring)
            ok(status == 401, 'Token expirado rejeitado')
            status, _, data = request('POST', '/api/v1/auth/login',
                                      {'username': 'testadmin', 'password': PASSWORD})
            ok(status == 200, 'Novo login depois da expiracao')
            rotating = data['access_token']
            rotated = cli(env, 'reset-password', NEW_PASSWORD)
            ok(rotated.returncode == 0, f'Rotacao local de senha: {rotated.stderr[-200:]}')
            status, _, _ = request('GET', '/api/v1/auth/me', token=rotating)
            ok(status == 401, 'Rotacao revoga todas as sessoes')
            status, _, _ = request('POST', '/api/v1/auth/login',
                                   {'username': 'testadmin', 'password': PASSWORD})
            ok(status == 401, 'Senha antiga revogada')
            status, _, _ = request('POST', '/api/v1/auth/login',
                                   {'username': 'testadmin', 'password': NEW_PASSWORD})
            ok(status == 200, 'Senha nova autentica')
        finally:
            stop(process)
    print('[OK] Fase 6.2 HTTP/SQLite: testes em banco temporario aprovados.')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, OSError, ValueError, KeyError, socket.error,
            subprocess.SubprocessError, sqlite3.Error) as error:
        print('[FALHOU]', error, file=sys.stderr)
        sys.exit(1)
