#!/usr/bin/env python3
"""Fase 5: testes de API REST em TCP real (stdlib Python apenas).

Uso: python3 tests/api_rest.py           # inicia/encerra servidor temporario
     python3 tests/api_rest.py --running # usa processo ja ativo na porta 8080
"""

import argparse
import concurrent.futures
import json
import socket
import subprocess
import sys
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOST, PORT = "127.0.0.1", 8080
PROCESS = None
LOG = None
TOKEN = uuid.uuid4().hex[:10]


def http(method, path, data=None, content_type="application/json", raw_headers=b"", include_length=True):
    if isinstance(data, (dict, list)):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    elif isinstance(data, str):
        body = data.encode("utf-8")
    elif isinstance(data, bytes):
        body = data
    else:
        body = b""
    head = f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n".encode("ascii")
    if content_type is not None:
        head += f"Content-Type: {content_type}\r\n".encode("ascii")
    if include_length:
        head += f"Content-Length: {len(body)}\r\n".encode("ascii")
    head += raw_headers + b"\r\n"
    with socket.create_connection((HOST, PORT), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(head + body)
        sock.shutdown(socket.SHUT_WR)
        received = bytearray()
        while True:
            part = sock.recv(8192)
            if not part:
                break
            received += part
    response_head, sep, response_body = bytes(received).partition(b"\r\n\r\n")
    if not sep:
        raise AssertionError(f"HTTP response without CRLFCRLF: {received[:150]!r}")
    lines = response_head.split(b"\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for line in lines[1:]:
        key, separator, value = line.partition(b":")
        if separator:
            headers.setdefault(key.decode().lower(), []).append(value.decode().strip())
    if "content-length" in headers:
        expected = int(headers["content-length"][0])
        if len(response_body) != expected:
            raise AssertionError(f"Content-Length {expected}, recebidos {len(response_body)} bytes")
    parsed = None
    if response_body and "application/json" in headers.get("content-type", [""])[0]:
        parsed = json.loads(response_body)
    return status, headers, response_body, parsed


class RestIntegration(unittest.TestCase):
    user_id = None
    secondary_id = None

    def test_01_existing_endpoints_unchanged(self):
        self.assertEqual(http("GET", "/health", content_type=None, include_length=False)[0], 200)
        self.assertEqual(http("GET", "/", content_type=None, include_length=False)[0], 200)
        self.assertEqual(http("GET", "/metrics", content_type=None, include_length=False)[0], 200)
        self.assertEqual(http("GET", "/pagina-inexistente", content_type=None, include_length=False)[0], 404)
        self.assertEqual(http("POST", "/users", data=b"hello=world", content_type=None)[0], 405)

    def test_02_collection_and_default_pagination(self):
        status, headers, _, payload = http("GET", "/api/v1/users", content_type=None, include_length=False)
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], ["application/json; charset=utf-8"])
        self.assertIsInstance(payload["data"], list)
        self.assertEqual(payload["pagination"]["limit"], 20)
        self.assertEqual(payload["pagination"]["offset"], 0)

    def test_03_post_creates_resource_with_location(self):
        status, headers, _, payload = http("POST", "/api/v1/users", {
            "name": "João Exemplo", "email": f"joao-{TOKEN}@example.com"})
        self.assertEqual(status, 201)
        self.assertGreater(payload["data"]["id"], 0)
        self.__class__.user_id = payload["data"]["id"]
        self.assertEqual(headers["location"], [f"/api/v1/users/{self.user_id}"])
        self.assertEqual(payload["data"]["name"], "João Exemplo")

    def test_04_get_resource(self):
        status, _, _, payload = http("GET", f"/api/v1/users/{self.user_id}", content_type=None)
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["email"], f"joao-{TOKEN}@example.com")

    def test_05_pagination(self):
        status, _, _, payload = http("GET", "/api/v1/users?limit=1&offset=0", content_type=None)
        self.assertEqual(status, 200)
        self.assertEqual(payload["pagination"]["limit"], 1)
        self.assertLessEqual(len(payload["data"]), 1)

    def test_06_duplicate_email_is_conflict(self):
        status, _, _, payload = http("POST", "/api/v1/users", {
            "name": "Duplicado", "email": f"JOAO-{TOKEN}@EXAMPLE.COM"})
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["code"], "email_conflict")

    def test_07_patch_partial_update(self):
        status, _, _, payload = http("PATCH", f"/api/v1/users/{self.user_id}", {"name": "Nome Atualizado"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["name"], "Nome Atualizado")
        self.assertEqual(payload["data"]["email"], f"joao-{TOKEN}@example.com")

    def test_08_put_full_update(self):
        status, _, _, payload = http("PUT", f"/api/v1/users/{self.user_id}", {
            "name": "Nome Completo", "email": f"novo-{TOKEN}@example.com"})
        self.assertEqual(status, 200)
        self.assertEqual(payload["data"]["email"], f"novo-{TOKEN}@example.com")

    def test_09_conflict_on_update(self):
        status, _, _, payload = http("POST", "/api/v1/users", {
            "name": "Outro", "email": f"outro-{TOKEN}@example.com"})
        self.assertEqual(status, 201)
        self.__class__.secondary_id = payload["data"]["id"]
        status, _, _, payload = http("PATCH", f"/api/v1/users/{self.user_id}", {
            "email": f"outro-{TOKEN}@example.com"})
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"]["code"], "email_conflict")

    def test_10_delete_returns_empty_204(self):
        status, headers, body, _ = http("DELETE", f"/api/v1/users/{self.user_id}", content_type=None)
        self.assertEqual(status, 204)
        self.assertEqual(body, b"")
        self.assertNotIn("content-length", headers)
        self.assertEqual(http("GET", f"/api/v1/users/{self.user_id}", content_type=None)[0], 404)
        self.assertEqual(http("DELETE", f"/api/v1/users/{self.secondary_id}", content_type=None)[0], 204)

    def test_11_malformed_json(self):
        status, _, _, payload = http("POST", "/api/v1/users", "{")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "invalid_json")

    def test_12_validation_missing_fields(self):
        self.assertEqual(http("POST", "/api/v1/users", {"name": "So Nome"})[0], 422)
        self.assertEqual(http("PATCH", "/api/v1/users/1", {})[0], 422)
        self.assertEqual(http("POST", "/api/v1/users", {"name": 1, "email": "a@b.com"})[0], 422)
        self.assertEqual(http("POST", "/api/v1/users", {"name": "A", "email": "invalid"})[0], 422)
        self.assertEqual(http("POST", "/api/v1/users", {"name": "A", "email": "a@b.com", "admin": True})[0], 422)

    def test_13_content_type_enforced(self):
        self.assertEqual(http("POST", "/api/v1/users", b"{}", "text/plain")[0], 415)
        self.assertEqual(http("POST", "/api/v1/users", b"{}", None)[0], 415)
        self.assertEqual(http("POST", "/api/v1/users", b"{}", "application/json; charset=utf-8")[0], 422)

    def test_14_length_required(self):
        status, _, _, payload = http("POST", "/api/v1/users", None, include_length=False)
        self.assertEqual(status, 411)
        self.assertEqual(payload["error"]["code"], "length_required")

    def test_15_json_payload_size(self):
        large = {"name": "x" * 4200, "email": "a@example.com"}
        self.assertEqual(http("POST", "/api/v1/users", large)[0], 413)

    def test_16_duplicate_content_type(self):
        status, _, _, payload = http("POST", "/api/v1/users", b"{}",
                                     raw_headers=b"Content-Type: text/plain\r\n")
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"]["code"], "bad_request")

    def test_17_invalid_id_and_unknown_route(self):
        self.assertEqual(http("GET", "/api/v1/users/abc", content_type=None)[0], 400)
        self.assertEqual(http("GET", "/api/v1/users/0", content_type=None)[0], 400)
        self.assertEqual(http("GET", "/api/v1/missing", content_type=None)[0], 404)

    def test_18_method_not_allowed_has_allow_header(self):
        status, headers, _, payload = http("DELETE", "/api/v1/users", content_type=None)
        self.assertEqual(status, 405)
        self.assertEqual(headers["allow"], ["GET, POST"])
        self.assertEqual(payload["error"]["code"], "method_not_allowed")

    def test_19_query_parameter_validation(self):
        self.assertEqual(http("GET", "/api/v1/users?limit=101", content_type=None)[0], 400)
        self.assertEqual(http("GET", "/api/v1/users?limit=1&limit=2", content_type=None)[0], 400)
        self.assertEqual(http("GET", "/api/v1/users?foo=1", content_type=None)[0], 400)

    def test_20_unsupported_get_body(self):
        self.assertEqual(http("GET", "/api/v1/users", b"hi", content_type=None)[0], 400)

    def test_21_concurrent_creation_unique_ids(self):
        emails = [f"parallel-{TOKEN}-{index}@example.com" for index in range(12)]
        def create_one(email):
            return http("POST", "/api/v1/users", {"name": "Paralelo", "email": email})
        with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(create_one, emails))
        self.assertTrue(all(status == 201 for status, _, _, _ in results), [s for s, _, _, _ in results])
        ids = [payload["data"]["id"] for _, _, _, payload in results]
        self.assertEqual(len(set(ids)), len(ids))
        for id_ in ids:
            self.assertEqual(http("DELETE", f"/api/v1/users/{id_}", content_type=None)[0], 204)


def start_server():
    global PROCESS, LOG
    try:
        with socket.create_connection((HOST, PORT), timeout=0.2):
            raise RuntimeError("Porta 8080 ocupada. Encerre cargo run antes de executar este teste (ou use --running).")
    except OSError:
        pass
    print("[FASE 5] Compilando release...", flush=True)
    subprocess.run(["cargo", "build", "--release"], cwd=ROOT, check=True)
    LOG = (ROOT / "api_server.log").open("w")
    PROCESS = subprocess.Popen([str(ROOT / "target" / "release" / "server")],
                               cwd=ROOT, stdout=LOG, stderr=subprocess.STDOUT)
    for _ in range(100):
        if PROCESS.poll() is not None:
            raise RuntimeError("Servidor encerrou inesperadamente. Veja api_server.log")
        try:
            with socket.create_connection((HOST, PORT), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("Servidor nao escutou em 127.0.0.1:8080")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--running", action="store_true", help="usar servidor Rust ja iniciado")
    args = parser.parse_args()
    try:
        if not args.running:
            start_server()
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(RestIntegration)
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
