#!/usr/bin/env python3
"""RBAC 6.3 fim-a-fim: executa SOMENTE bancos temporarios.
Requer porta 8080 livre; nao utiliza e nao altera ~/server/data/.
"""
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
PASSWORD = 'segredo-temporario-de-testes-63'


def ok(assertion, description):
    if not assertion:
        raise AssertionError(description)
    print('[OK]', description)


def port_open():
    try:
        with socket.create_connection((HOST, PORT), timeout=.15):
            return True
    except OSError:
        return False


def request(method, target, body=None, token=None, extra_headers=None):
    headers = {'Host': 'localhost'}
    data = None
    if body is not None:
        data = json.dumps(body).encode('utf8')
        headers['Content-Type'] = 'application/json'
    if token is not None:
        headers['Authorization'] = f'Bearer {token}'
    headers.update(extra_headers or {})
    conn = http.client.HTTPConnection(HOST, PORT, timeout=8)
    try:
        conn.request(method, target, body=data, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        result_headers = dict(response.getheaders())
        try:
            result = json.loads(raw) if raw else None
        except (ValueError, UnicodeDecodeError):
            result = raw.decode('utf8', errors='replace')
        return response.status, result_headers, result
    finally:
        conn.close()


def expect(method, target, status, *, token=None, body=None):
    actual, headers, result = request(method, target, token=token, body=body)
    ok(actual == status, f'{method} {target}: esperado {status}, obtido {actual}, resposta {str(result)[:100]}')
    return headers, result


def boot(env):
    process = subprocess.Popen([str(SERVER)], cwd=ROOT, env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(150):
        if process.poll() is not None:
            raise AssertionError('Servidor encerrou: ' + process.stderr.read().decode(errors='replace')[-1200:])
        if port_open():
            return process
        time.sleep(.05)
    stop(process)
    raise AssertionError('Servidor nao iniciou em tempo habil')


def stop(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if process.stderr:
        process.stderr.close()
    for _ in range(50):
        if not port_open():
            break
        time.sleep(.05)


def login(name):
    status, headers, result = request('POST', '/api/v1/auth/login',
                                      {'username': name, 'password': PASSWORD})
    ok(status == 200 and isinstance(result, dict) and len(result.get('access_token', '')) == 64,
       f'Login para {name} aceita a conta de teste')
    ok(headers.get('Cache-Control') == 'no-store', 'Login nao permite cache')
    return result['access_token']


def main():
    ok(not port_open(), 'Porta 8080 livre; nenhum servidor real sera interrompido')
    ok(SERVER.is_file() and ADMIN.is_file(), 'Binarios release presentes')
    with tempfile.TemporaryDirectory(prefix='rust-auth63-') as folder:
        temporary = Path(folder)
        users = temporary / 'users.sqlite3'
        auth = temporary / 'auth' / 'auth.sqlite3'
        env = os.environ.copy()
        env['RUST_SERVER_DB_PATH'] = str(users)
        env['RUST_SERVER_AUTH_DB_PATH'] = str(auth)
        server = None
        try:
            server = boot(env)
            expect('GET', '/health', 200)
            headers, _ = expect('GET', '/api/v1/users', 401)
            ok(headers.get('WWW-Authenticate') == 'Bearer realm="rust-server"',
               '401 envia desafio Bearer')
            expect('POST', '/api/v1/users', 401, body={'name':'Ana','email':'ana@example.com'})
            expect('GET', '/api/v1/users/1', 401)
            expect('GET', '/api/v1/users?limit=1', 401)
            expect('GET', '/api/v1/users', 401, token='x' * 64)
            expect('GET', '/api/v1/auth/me', 401)
            stop(server)
            server = None

            ok(auth.is_file(), 'SQLite auth de teste criado')
            created = subprocess.run([str(ADMIN), 'bootstrap', 'testadmin', '--password-stdin'],
                                     input=PASSWORD+'\n', text=True, cwd=ROOT, env=env,
                                     capture_output=True, timeout=20)
            ok(created.returncode == 0, 'Administrador criado SOMENTE no banco temporario')
            with sqlite3.connect(auth) as db:
                password_hash = db.execute('SELECT password_hash FROM auth_accounts WHERE username = ?',
                                           ('testadmin',)).fetchone()[0]
                ok(password_hash.startswith('$argon2id$'), 'Argon2id conservado')
                # Apenas fixture: as contas do laboratorio nao sao alteradas.
                for username, role in [('testviewer','viewer'), ('testeditor','editor')]:
                    db.execute('INSERT INTO auth_accounts(username, password_hash, role) VALUES (?,?,?)',
                               (username, password_hash, role))
            server = boot(env)
            viewer = login('testviewer')
            editor = login('testeditor')
            admin = login('testadmin')
            expect('GET', '/api/v1/auth/me', 200, token=viewer)
            expect('GET', '/api/v1/auth/me', 200, token=admin)

            expect('GET', '/api/v1/users', 200, token=viewer)
            for method, route, body in [
                ('POST', '/api/v1/users', {'name':'Ana','email':'ana@example.com'}),
                ('PUT', '/api/v1/users/1', {'name':'Ana','email':'ana@example.com'}),
                ('PATCH', '/api/v1/users/1', {'name':'Nova'}),
                ('DELETE', '/api/v1/users/1', None),
            ]:
                headers, _ = expect(method, route, 403, token=viewer, body=body)
                ok('WWW-Authenticate' not in headers, '403 nao dispara desafio de login')
            expect('GET', '/api/v1/users', 200, token=editor)
            _, created = expect('POST','/api/v1/users',201, token=editor,
                                body={'name':'Ana Silva','email':'ana@example.com'})
            user_id = created['data']['id']
            expect('GET', f'/api/v1/users/{user_id}', 200, token=viewer)
            expect('PATCH', f'/api/v1/users/{user_id}', 200, token=editor,
                   body={'name':'Ana Atualizada'})
            expect('PUT', f'/api/v1/users/{user_id}', 200, token=editor,
                   body={'name':'Ana Completa','email':'ana2@example.com'})
            expect('DELETE', f'/api/v1/users/{user_id}', 403, token=editor)
            expect('DELETE', f'/api/v1/users/{user_id}', 204, token=admin)
            expect('GET', f'/api/v1/users/{user_id}', 404, token=admin)
            expect('GET', '/api/v1/users/999999', 401)  # sem revelar existencia
            expect('GET', '/api/v1/users-other', 404)
            expect('GET', '/api/v1/auth/me', 200, token=admin)

            # Desativacao/alteracao de papel valem imediatamente, mesmo com sessao antiga.
            with sqlite3.connect(auth) as db:
                db.execute('UPDATE auth_accounts SET role = ? WHERE username = ?',
                           ('viewer', 'testeditor'))
            expect('POST', '/api/v1/users', 403, token=editor,
                   body={'name':'SemPermissao','email':'blocked@example.com'})
            expect('GET', '/api/v1/users', 200, token=editor)
            with sqlite3.connect(auth) as db:
                db.execute('UPDATE auth_accounts SET is_active = 0 WHERE username = ?', ('testviewer',))
            expect('GET', '/api/v1/users', 401, token=viewer)
            expect('GET', '/api/v1/auth/me', 401, token=viewer)

            # Expiracao respeita CHECK expires_at > created_at.
            with sqlite3.connect(auth) as db:
                db.execute('UPDATE auth_sessions SET created_at = unixepoch() - 7200, '
                           'expires_at = unixepoch() - 3600 WHERE account_id = '
                           '(SELECT id FROM auth_accounts WHERE username = ?)', ('testeditor',))
            expect('GET', '/api/v1/users', 401, token=editor)
            expect('POST', '/api/v1/auth/logout', 204, token=admin)
            expect('GET', '/api/v1/users', 401, token=admin)
            admin2 = login('testadmin')
            stop(server)
            server = boot(env)
            expect('GET', '/api/v1/users', 200, token=admin2)
            ok(users.is_file() and auth.is_file(), 'SQLite de cadastro e autenticacao isolados')
        finally:
            stop(server)
    print('[OK] Fase 6.3: RBAC e autenticacao validada sem acessar bancos reais')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('[FALHOU]', exc, file=sys.stderr)
        sys.exit(1)
