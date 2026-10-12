#!/usr/bin/env python3
"""Testes de integracao HTTP/TCP (somente stdlib Python).

Padrao: compila com Cargo, inicia e encerra uma instancia isolada em 127.0.0.1:8080.
Execute da raiz do projeto: python3 tests/integration_http.py
Opcoes: --running (servidor ja iniciado); --quick (nao testar timeouts); --stress (teste de 503 com >144 conexoes)
"""
import argparse
import socket
import select
import subprocess
import sys
import time
import unittest
from pathlib import Path

HOST, PORT = "127.0.0.1", 8080
ROOT = Path(__file__).resolve().parents[1]
FLAGS = argparse.Namespace(running=False, quick=False, stress=False)
PROCESS = None
LOG = None


def http_raw(data: bytes, *, timeout=9, fragments=None):
    with socket.create_connection((HOST, PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if fragments is None:
            sock.sendall(data)
        else:
            for part in fragments:
                sock.sendall(part)
                time.sleep(0.1)
        sock.shutdown(socket.SHUT_WR)
        raw = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            raw.extend(chunk)
    head, sep, body = bytes(raw).partition(b"\r\n\r\n")
    if not sep:
        raise AssertionError(f"Resposta sem separador HTTP: {bytes(raw[:100])!r}")
    lines = head.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        headers[name.lower()] = value.strip()
    if b"content-length" in headers:
        expected = int(headers[b"content-length"])
        assert len(body) == expected, (len(body), expected)
    return status, headers, body


def request(path="/", method="GET", extra_headers=b"", body=b""):
    req = (f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n".encode()
           + extra_headers + b"\r\n" + body)
    return http_raw(req)


class HTTPIntegration(unittest.TestCase):
    def test_01_health(self):
        code, headers, body = request("/health")
        self.assertEqual(code, 200)
        self.assertEqual(body, b"ok\n")
        self.assertIn(b"text/plain", headers[b"content-type"])

    def test_02_home(self):
        code, _, body = request("/")
        self.assertEqual(code, 200)
        self.assertIn(b"Home", body)

    def test_03_about(self):
        code, _, _ = request("/about")
        self.assertEqual(code, 200)

    def test_04_not_found(self):
        code, _, _ = request("/pagina-inexistente")
        self.assertEqual(code, 404)

    def test_05_method_not_allowed(self):
        code, _, _ = request("/users", "POST", b"Content-Length: 11\r\n", b"hello=world")
        self.assertEqual(code, 405)

    def test_06_missing_host(self):
        code, _, _ = http_raw(b"GET / HTTP/1.1\r\n\r\n")
        self.assertEqual(code, 400)

    def test_07_invalid_header(self):
        code, _, _ = request("/", extra_headers=b"Malformado\r\n")
        self.assertEqual(code, 400)

    def test_08_duplicate_content_length(self):
        code, _, _ = request("/", extra_headers=b"Content-Length: 1\r\nContent-Length: 2\r\n")
        self.assertEqual(code, 400)

    def test_09_transfer_encoding(self):
        code, _, _ = request("/", extra_headers=b"Transfer-Encoding: chunked\r\n")
        self.assertEqual(code, 400)

    def test_10_invalid_content_length(self):
        code, _, _ = request("/", extra_headers=b"Content-Length: abc\r\n")
        self.assertEqual(code, 400)

    def test_11_payload_too_large(self):
        code, _, _ = request("/", extra_headers=b"Content-Length: 999999\r\n")
        self.assertEqual(code, 413)

    def test_12_fragmented_headers(self):
        parts = [b"GET / HTTP/1.1\r\n", b"Host: local", b"host\r\n", b"\r\n"]
        code, _, _ = http_raw(b"", fragments=parts)
        self.assertEqual(code, 200)

    def test_13_fragmented_body(self):
        parts = [b"POST /users HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\n",
                 b"hello", b"=wor", b"ld"]
        code, _, _ = http_raw(b"", fragments=parts)
        self.assertEqual(code, 405)

    def test_14_metrics(self):
        code, headers, body = request("/metrics")
        self.assertEqual(code, 200)
        self.assertIn(b"text/plain", headers[b"content-type"])
        for name in (b"rust_http_workers_active", b"rust_http_queue_depth",
                     b"rust_http_connections_accepted_total", b"rust_http_responses_total",
                     b"rust_http_response_duration_seconds_bucket"):
            self.assertIn(name, body)
        self.assertIn(b'rust_http_responses_total{status="404"}', body)
        def count_404(metrics_body):
            prefix = b'rust_http_responses_total{status="404"} '
            return int(next(line.split(b" ")[1] for line in metrics_body.splitlines() if line.startswith(prefix)))
        before = count_404(body)
        request("/pagina-ainda-inexistente")
        _, _, newer = request("/metrics")
        self.assertGreaterEqual(count_404(newer), before + 1)

    def test_15_read_timeout(self):
        if FLAGS.quick:
            self.skipTest("--quick")
        with socket.create_connection((HOST, PORT), timeout=9) as sock:
            sock.settimeout(9)
            sock.sendall(b"GET / HTTP/1.1\r\n")
            raw = sock.recv(4096)
            self.assertTrue(raw.startswith(b"HTTP/1.1 408 "), raw)

    def test_16_body_timeout(self):
        if FLAGS.quick:
            self.skipTest("--quick")
        with socket.create_connection((HOST, PORT), timeout=9) as sock:
            sock.settimeout(9)
            sock.sendall(b"POST /users HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\nhello")
            raw = sock.recv(4096)
            self.assertTrue(raw.startswith(b"HTTP/1.1 408 "), raw)

    def test_17_overload(self):
        if not FLAGS.stress:
            self.skipTest("Opcional: --stress")
        clients = []
        try:
            # 16 workers + fila 128 + excedentes para provocar HTTP 503.
            for _ in range(170):
                sock = socket.create_connection((HOST, PORT), timeout=2)
                sock.settimeout(1)
                sock.sendall(b"GET / HTTP/1.1\r\n")
                clients.append(sock)
            statuses = []
            ready, _, _ = select.select(clients[-26:], [], [], 2)
            for sock in ready:
                try:
                    raw = sock.recv(4096)
                    if raw.startswith(b"HTTP/1.1 "):
                        statuses.append(int(raw.split()[1]))
                except (OSError, ValueError):
                    pass
            self.assertIn(503, statuses, f"Esperado 503; recebidos: {statuses}")
        finally:
            for sock in clients:
                sock.close()


def startup():
    global PROCESS, LOG
    try:
        with socket.create_connection((HOST, PORT), timeout=0.2):
            raise RuntimeError("Porta 8080 ocupada. Encerre o servidor antigo, ou use --running.")
    except (ConnectionRefusedError, TimeoutError, OSError):
        pass
    print("[FASE 3] Compilando release...", flush=True)
    subprocess.run(["cargo", "build", "--release"], cwd=ROOT, check=True)
    LOG = open(ROOT / "integration_server.log", "w", encoding="utf-8")
    binary = ROOT / "target" / "release" / "server"
    PROCESS = subprocess.Popen([str(binary)], cwd=ROOT, stdout=LOG, stderr=subprocess.STDOUT)
    for _ in range(100):
        if PROCESS.poll() is not None:
            raise RuntimeError("Servidor encerrou durante o inicio. Veja integration_server.log")
        try:
            with socket.create_connection((HOST, PORT), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Servidor nao abriu a porta 8080. Veja integration_server.log")


def main():
    global FLAGS
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--running", action="store_true", help="Usa servidor previamente iniciado")
    parser.add_argument("--quick", action="store_true", help="Pula dois testes de timeout (~10s)")
    parser.add_argument("--stress", action="store_true", help="Adiciona teste de 503 sob saturacao")
    FLAGS = parser.parse_args()
    try:
        if not FLAGS.running:
            startup()
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(HTTPIntegration)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1
    finally:
        if PROCESS is not None:
            PROCESS.terminate()
            try:
                PROCESS.wait(timeout=3)
            except subprocess.TimeoutExpired:
                PROCESS.kill()
                PROCESS.wait()
        if LOG is not None:
            LOG.close()


if __name__ == "__main__":
    sys.exit(main())
