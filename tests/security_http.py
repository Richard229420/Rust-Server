#!/usr/bin/env python3
"""Fase 4: testes negativos HTTP/TCP sem dependencias externas.

Executar: python3 tests/security_http.py
         python3 tests/security_http.py --running
"""
import argparse
import socket
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST, PORT = "127.0.0.1", 8080
PROCESS = None
LOG = None


def exchange(data, timeout=4):
    with socket.create_connection((HOST, PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            packet = sock.recv(4096)
            if not packet:
                break
            response.extend(packet)
    head, sep, body = bytes(response).partition(b"\r\n\r\n")
    if not sep:
        raise AssertionError(f"Resposta HTTP sem cabecalhos: {bytes(response[:120])!r}")
    line = head.split(b"\r\n", 1)[0]
    status = int(line.split(b" ")[1])
    return status, head.lower(), body


def request(path=b"/", extra=b"", method=b"GET"):
    return exchange(method + b" " + path + b" HTTP/1.1\r\nHost: localhost\r\n" + extra + b"\r\n")


class HTTPSecurityIntegration(unittest.TestCase):
    def assert_rejected(self, message):
        status, _, _ = exchange(message)
        self.assertEqual(status, 400, f"Esperado 400, obtido {status}: {message!r}")

    def test_01_health_still_works(self):
        self.assertEqual(request(b"/health")[0], 200)

    def test_02_security_headers_success(self):
        status, headers, _ = request()
        self.assertEqual(status, 200)
        for h in [b"x-content-type-options: nosniff", b"x-frame-options: deny",
                  b"referrer-policy: no-referrer", b"content-security-policy:"]:
            self.assertIn(h, headers)
        self.assertNotIn(b"strict-transport-security", headers)

    def test_03_security_headers_on_error(self):
        status, headers, _ = request(b"/missing-1234")
        self.assertEqual(status, 404)
        self.assertIn(b"x-content-type-options: nosniff", headers)

    def test_04_duplicate_host(self):
        self.assert_rejected(b"GET / HTTP/1.1\r\nHost: localhost\r\nHost: attacker.example\r\n\r\n")

    def test_05_invalid_host(self):
        self.assert_rejected(b"GET / HTTP/1.1\r\nHost: test@evil.example\r\n\r\n")

    def test_06_ambiguous_header_name(self):
        self.assert_rejected(b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length : 0\r\n\r\n")

    def test_07_obs_fold(self):
        self.assert_rejected(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Foo: a\r\n b\r\n\r\n")

    def test_08_malformed_line(self):
        self.assert_rejected(b"GET  / HTTP/1.1\r\nHost: localhost\r\n\r\n")

    def test_09_http10_unsupported(self):
        self.assert_rejected(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")

    def test_10_no_absolute_form(self):
        self.assert_rejected(b"GET http://example.com/ HTTP/1.1\r\nHost: localhost\r\n\r\n")

    def test_11_path_traversal(self):
        for value in [b"/../etc/passwd", b"/x/%2e%2e/secret", b"/%2e./secret", b"/%252e%252e/"]:
            with self.subTest(path=value):
                self.assertEqual(request(value)[0], 400)

    def test_12_encoded_slash(self):
        self.assertEqual(request(b"/x%2fy")[0], 400)

    def test_13_transfer_encoding(self):
        self.assertEqual(request(extra=b"Transfer-Encoding: chunked\r\nContent-Length: 0\r\n")[0], 400)

    def test_14_multiple_lengths(self):
        self.assertEqual(request(extra=b"Content-Length: 0\r\nContent-Length: 0\r\n")[0], 400)

    def test_15_expect_not_supported(self):
        self.assertEqual(request(extra=b"Expect: 100-continue\r\n")[0], 400)

    def test_16_upgrade_not_supported(self):
        self.assertEqual(request(extra=b"Upgrade: websocket\r\n")[0], 400)

    def test_17_non_ascii_header(self):
        self.assertEqual(request(extra=b"X-Header: \xff\r\n")[0], 400)

    def test_18_valid_body_preserved(self):
        # /users ainda nao aceita POST, mas o framing correto nao deve ser
        # confundido com bad request.
        raw = b"POST /users HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\nhello=world"
        self.assertEqual(exchange(raw)[0], 405)


def start():
    global PROCESS, LOG
    try:
        with socket.create_connection((HOST, PORT), timeout=0.25):
            raise RuntimeError("Porta 8080 ocupada. Encerre o servidor, ou use --running.")
    except (ConnectionRefusedError, TimeoutError, OSError):
        pass
    subprocess.run(["cargo", "build", "--release"], cwd=ROOT, check=True)
    LOG = open(ROOT / "security_server.log", "w", encoding="utf-8")
    PROCESS = subprocess.Popen([str(ROOT / "target" / "release" / "server")],
                               cwd=ROOT, stdout=LOG, stderr=subprocess.STDOUT)
    for _ in range(100):
        if PROCESS.poll() is not None:
            raise RuntimeError("Servidor encerrou; veja security_server.log")
        try:
            with socket.create_connection((HOST, PORT), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Servidor nao abriu a porta 8080")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--running", action="store_true", help="Usar servidor atual")
    args = parser.parse_args()
    try:
        if not args.running:
            start()
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(HTTPSecurityIntegration)
        return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1
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
