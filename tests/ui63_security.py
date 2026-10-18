#!/usr/bin/env python3
"""Proxy Swagger da Fase 6.3: confere Bearer e escopo, sem banco real."""
import http.client
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
TOKEN = 'a' * 64


class FakeRust(BaseHTTPRequestHandler):
    received = []
    def log_message(self, *_):
        pass

    def dispatch(self):
        length = int(self.headers.get('Content-Length','0'))
        data = self.rfile.read(length) if length else b''
        auth = self.headers.get('Authorization')
        FakeRust.received.append((self.command, self.path, auth, self.headers.get('X-Lab-Token')))
        if self.path == '/api/v1/auth/login':
            status, body = 200, json.dumps({'access_token':TOKEN, 'token_type':'Bearer'}).encode()
        elif auth != 'Bearer ' + TOKEN:
            status, body = 401, b'{"error":{"code":"unauthorized"}}'
        elif self.path == '/api/v1/auth/logout':
            status, body = 204, b''
        else:
            status, body = 200, b'{"data":[]}'
        self.send_response(status)
        if status == 401:
            self.send_header('WWW-Authenticate', 'Bearer realm="rust-server"')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self): self.dispatch()
    def do_POST(self): self.dispatch()
    def do_DELETE(self): self.dispatch()


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='auth63-ui-')
        cls.root = Path(cls.temp.name)
        (cls.root/'scripts').mkdir()
        (cls.root/'docs/ui').mkdir(parents=True)
        for path in (ROOT/'docs/ui').iterdir():
            shutil.copy2(path, cls.root/'docs/ui'/path.name)
        shutil.copy2(ROOT/'docs/openapi.json', cls.root/'docs/openapi.json')
        shutil.copy2(ROOT/'scripts/swagger_lab.py', cls.root/'scripts/swagger_lab.py')
        cls.rust = ThreadingHTTPServer(('127.0.0.1', 0), FakeRust)
        cls.thread = threading.Thread(target=cls.rust.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = free_port()
        cls.process = subprocess.Popen([sys.executable, str(cls.root/'scripts/swagger_lab.py'),
                 '--root', str(cls.root), '--port', str(cls.port),
                 '--backend-port', str(cls.rust.server_port)],
                 stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            for _ in range(120):
                if cls.process.poll() is not None:
                    raise RuntimeError(cls.process.stderr.read().decode())
                try:
                    conn = http.client.HTTPConnection('127.0.0.1', cls.port, timeout=.3)
                    conn.request('GET','/offline')
                    response = conn.getresponse()
                    content = response.read().decode()
                    conn.close()
                    match = re.search(r'<meta name="lab-token" content="([^"]+)"', content)
                    if match:
                        cls.lab_token = match.group(1)
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise RuntimeError('Proxy nao iniciou')
        except BaseException:
            cls.process.terminate()
            cls.process.wait(timeout=3)
            cls.rust.shutdown()
            cls.rust.server_close()
            cls.temp.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        try: cls.process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cls.process.kill(); cls.process.wait(timeout=3)
        cls.process.stderr.close()
        cls.rust.shutdown()
        cls.rust.server_close()
        cls.temp.cleanup()

    def req(self, method, route, body=None, headers=None):
        headers = dict(headers or {})
        headers['Host'] = f'127.0.0.1:{self.port}'
        conn = http.client.HTTPConnection('127.0.0.1', self.port, timeout=5)
        try:
            conn.request(method, route, body=body, headers=headers)
            response = conn.getresponse()
            status = response.status
            response_headers = dict(response.getheaders())
            payload = response.read()
            return status, response_headers, payload
        finally:
            conn.close()

    def test_01_requires_lab_token_even_with_bearer(self):
        self.assertEqual(self.req('GET','/api/v1/users',headers={'Authorization':'Bearer '+TOKEN})[0],403)

    def test_02_no_bearer_reaches_rust_as_401(self):
        status, headers, _ = self.req('GET','/api/v1/users',headers={'X-Lab-Token':self.lab_token})
        self.assertEqual(status, 401)
        self.assertEqual(headers.get('WWW-Authenticate'), 'Bearer realm="rust-server"')

    def test_03_bearer_forwarded_without_lab_secret(self):
        status, _, _ = self.req('GET','/api/v1/users', headers={
            'X-Lab-Token':self.lab_token, 'Authorization':'Bearer '+TOKEN})
        self.assertEqual(status,200)
        self.assertIn(('GET','/api/v1/users','Bearer '+TOKEN,None),FakeRust.received)

    def test_04_login_and_logout_through_allowlist(self):
        status,_,_ = self.req('POST','/api/v1/auth/login', body=b'{"username":"test","password":"test"}',
                              headers={'X-Lab-Token':self.lab_token,'Content-Type':'application/json'})
        self.assertEqual(status,200)
        status,_,payload = self.req('POST','/api/v1/auth/logout',
                              headers={'X-Lab-Token':self.lab_token,'Authorization':'Bearer '+TOKEN})
        self.assertEqual(status,204)
        self.assertEqual(payload,b'')

    def test_05_scope_origin_restrictions_and_bad_bearer(self):
        self.assertEqual(self.req('GET','/metrics',headers={'X-Lab-Token':self.lab_token})[0],404)
        self.assertEqual(self.req('GET','/api/v1/admin',headers={'X-Lab-Token':self.lab_token})[0],404)
        self.assertEqual(self.req('GET','/api/v1/users', headers={
            'X-Lab-Token':self.lab_token, 'Origin':'https://evil.example',
            'Authorization':'Bearer '+TOKEN})[0],403)
        self.assertEqual(self.req('GET','/api/v1/users', headers={
            'X-Lab-Token':self.lab_token, 'Authorization':'Bearer abc'})[0],400)

    def test_06_docs_js_and_spec(self):
        self.assertIn(b'BearerAuth', self.req('GET','/openapi.json')[2])
        self.assertIn(b'Authorization', self.req('GET','/assets/offline.js')[2])
        self.assertIn(b'/api/v1/auth/login', self.req('GET','/assets/swagger-init.js')[2])


if __name__ == '__main__':
    unittest.main(verbosity=2)
