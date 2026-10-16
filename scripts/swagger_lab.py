#!/usr/bin/env python3
"""Interface local OpenAPI 3.1.1 + proxy de escopo restrito para Rust.

Uso na raiz do projeto: python3 scripts/swagger_lab.py [--port 8765]
Somente loopback. Nao publica a API externamente.
"""
import argparse
import hmac
import http.client
import json
import re
import secrets
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
FILES = {
    '/assets/style.css': ('docs/ui/style.css', 'text/css; charset=utf-8'),
    '/assets/swagger-init.js': ('docs/ui/swagger-init.js', 'application/javascript; charset=utf-8'),
    '/assets/offline.js': ('docs/ui/offline.js', 'application/javascript; charset=utf-8'),
}
API_PATH = re.compile(r'^/api/v1/users(?:/[^/]*)?/?$')
METHODS = {'GET', 'POST', 'PUT', 'PATCH', 'DELETE'}


def serve(*, port=8765, backend_port=8080, root=ROOT, verbose=True):
    if not 1 <= port <= 65535 or not 1 <= backend_port <= 65535:
        raise ValueError('Portas devem estar entre 1 e 65535')
    root = Path(root).resolve()
    document = root / 'docs/openapi.json'
    if not document.is_file():
        raise RuntimeError(f'Fase 5.3 ausente: {document}')
    spec = json.loads(document.read_text(encoding='utf-8'))
    if spec.get('openapi') != '3.1.1':
        raise RuntimeError('Esperado OpenAPI 3.1.1 da Fase 5.3')
    for rel, _ in FILES.values():
        if not (root / rel).is_file():
            raise RuntimeError(f'Arquivo da UI ausente: {rel}')
    token = secrets.token_urlsafe(32)
    allowed_host = {f'127.0.0.1:{port}', f'localhost:{port}'}
    origins = {f'http://{host}' for host in allowed_host}

    class Handler(BaseHTTPRequestHandler):
        server_version = 'RustLabUI/5.4'
        sys_version = ''
        protocol_version = 'HTTP/1.1'

        def log_message(self, fmt, *args):
            if verbose:
                super().log_message(fmt, *args)

        def respond(self, status, payload=b'', ctype='text/plain; charset=utf-8', extra=None):
            self.send_response(status)
            self.send_header('Content-Type', ctype)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('X-Frame-Options', 'DENY')
            self.send_header('Referrer-Policy', 'no-referrer')
            self.send_header('Cross-Origin-Resource-Policy', 'same-origin')
            self.send_header('Content-Security-Policy',
                "default-src 'none'; script-src 'self' https://cdn.jsdelivr.net; "
                "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
                "img-src 'self' data:; font-src 'self' data:; "
                "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            if extra:
                for key, value in extra.items():
                    if key.lower() in {'content-type', 'content-length', 'transfer-encoding', 'connection',
                                      'server', 'date', 'cache-control', 'content-security-policy',
                                      'x-content-type-options', 'x-frame-options', 'referrer-policy',
                                      'cross-origin-resource-policy', 'access-control-allow-origin'}:
                        continue
                    self.send_header(key, value)
            self.end_headers()
            if payload:
                self.wfile.write(payload)

        def valid_host(self):
            host = self.headers.get('Host', '')
            return host in allowed_host and len(self.headers.get_all('Host', [])) == 1

        def dispatch(self):
            if not self.valid_host():
                self.respond(403, b'Host nao permitido')
                return
            parsed = urlsplit(self.path)
            path = parsed.path
            if path == '/' and self.command == 'GET':
                self.respond(302, extra={'Location':'/docs'})
                return
            if path in ('/docs', '/offline') and self.command == 'GET':
                relative = 'docs/ui/index.html' if path == '/docs' else 'docs/ui/offline.html'
                html = (root / relative).read_text(encoding='utf-8').replace('__LAB_TOKEN__', token)
                self.respond(200, html.encode('utf-8'), 'text/html; charset=utf-8')
                return
            if path in FILES and self.command == 'GET':
                rel, ctype = FILES[path]
                self.respond(200, (root / rel).read_bytes(), ctype)
                return
            if path == '/openapi.json' and self.command == 'GET':
                # O documento canonico NUNCA e alterado; uma copia apenas aponta para a mesma origem.
                copy = json.loads(document.read_text(encoding='utf-8'))
                copy['servers'] = [{'url': '/', 'description': 'Proxy local exclusivo do Swagger Lab (:8765)'}]
                self.respond(200, json.dumps(copy, ensure_ascii=False).encode('utf-8'),
                             'application/json; charset=utf-8')
                return
            if API_PATH.fullmatch(path) and self.command in METHODS:
                self.proxy(parsed)
                return
            self.respond(404, b'Rota nao encontrada')

        def proxy(self, parsed):
            supplied = self.headers.get('X-Lab-Token', '')
            if not hmac.compare_digest(supplied, token):
                self.respond(403, b'Token da interface ausente ou invalido')
                return
            origin = self.headers.get('Origin')
            if origin is not None and origin not in origins:
                self.respond(403, b'Origem nao permitida')
                return
            site = self.headers.get('Sec-Fetch-Site')
            if site and site not in {'same-origin', 'none'}:
                self.respond(403, b'Solicitacao cross-site bloqueada')
                return
            size = self.headers.get('Content-Length')
            if self.headers.get('Transfer-Encoding'):
                self.respond(400, b'Transfer-Encoding nao permitido')
                return
            if size is not None:
                try:
                    length = int(size)
                except ValueError:
                    self.respond(400, b'Content-Length invalido')
                    return
                if length < 0 or length > 8192:
                    self.respond(413, b'Corpo acima do limite da interface')
                    return
                body = self.rfile.read(length)
                if len(body) != length:
                    self.respond(400, b'Corpo incompleto')
                    return
            else:
                if self.command in {'POST','PUT','PATCH'}:
                    self.respond(411, b'Content-Length necessario')
                    return
                body = None
            headers = {'Accept': self.headers.get('Accept', 'application/json')}
            content_type = self.headers.get('Content-Type')
            if content_type:
                headers['Content-Type'] = content_type
            if body is not None:
                headers['Content-Length'] = str(len(body))
            target = parsed.path + (f'?{parsed.query}' if parsed.query else '')
            try:
                connection = http.client.HTTPConnection('127.0.0.1', backend_port, timeout=8)
                try:
                    connection.request(self.command, target, body=body, headers=headers)
                    upstream = connection.getresponse()
                    payload = upstream.read(32768 + 1)
                    if len(payload) > 32768:
                        self.respond(502, b'Resposta muito grande do Rust')
                        return
                    keep = {}
                    for key, val in upstream.getheaders():
                        if key.lower() in {'location', 'allow'}:
                            keep[key] = val
                    self.respond(upstream.status, payload,
                                 upstream.getheader('Content-Type', 'application/json; charset=utf-8'), keep)
                finally:
                    connection.close()
            except (OSError, http.client.HTTPException) as error:
                self.respond(502, json.dumps({'error': {'code':'backend_unavailable',
                             'message':'Rust indisponivel em 127.0.0.1:' + str(backend_port)}}).encode(),
                             'application/json; charset=utf-8')
                if verbose:
                    print(f'[UI] Backend indisponivel: {error}', file=sys.stderr)

        def do_GET(self): self.dispatch()
        def do_POST(self): self.dispatch()
        def do_PUT(self): self.dispatch()
        def do_PATCH(self): self.dispatch()
        def do_DELETE(self): self.dispatch()
        def do_HEAD(self): self.respond(405, b'Metodo nao permitido')
        def do_OPTIONS(self): self.respond(405, b'Sem CORS')

    httpd = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    httpd.daemon_threads = True
    print(f'[UI] Swagger: http://127.0.0.1:{port}/docs')
    print(f'[UI] Alternativa offline: http://127.0.0.1:{port}/offline')
    print(f'[UI] Encaminhando somente /api/v1/users* a 127.0.0.1:{backend_port}')
    try:
        httpd.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--port', type=int, default=8765, help='Porta local da interface (default: 8765)')
    p.add_argument('--backend-port', type=int, default=8080, help='Porta do Rust no loopback (default: 8080)')
    p.add_argument('--root', type=Path, default=ROOT, help='Raiz do projeto; usado tambem nos autotestes')
    args = p.parse_args()
    try:
        serve(port=args.port, backend_port=args.backend_port, root=args.root)
    except (OSError, ValueError, RuntimeError) as e:
        p.exit(1, f'[ERRO] {e}\n')

if __name__ == '__main__':
    main()
