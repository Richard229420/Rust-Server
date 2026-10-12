#!/usr/bin/env python3
"""Verifica TLS local do Caddy, rotas e ausencia de security headers duplicados.

Uso recomendado (sem desabilitar a verificacao do certificado):
  python3 tests/https_tls.py --ca-file "$HOME/.local/share/caddy/pki/authorities/local/root.crt"

A CA local deve pertencer ao Caddy em execucao e seu certificado raiz deve ser
obtido de fonte confiavel. Nao publique chaves privadas ou a CA no repositorio.
"""

import argparse
import http.client
import ssl
import sys
from pathlib import Path

SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy": "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
}


def request(path: str, context: ssl.SSLContext):
    connection = http.client.HTTPSConnection("localhost", 8443, context=context, timeout=8)
    try:
        connection.connect()
        tls_version = connection.sock.version()
        connection.request("GET", path)
        response = connection.getresponse()
        status = response.status
        body = response.read()
        headers = response.headers
        return status, body, tls_version, headers
    finally:
        connection.close()


def check_headers(headers, path):
    for name, expected in SECURITY_HEADERS.items():
        values = headers.get_all(name, [])
        assert len(values) == 1, (
            f"{path}: esperado 1 header {name}, recebidos {len(values)}: {values}"
        )
        assert values[0] == expected, (
            f"{path}: header {name} inesperado: {values[0]!r} != {expected!r}"
        )
    print(f"[OK] {path}: 4 headers de seguranca presentes uma unica vez")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--ca-file", type=Path,
        help="Certificado raiz PEM da CA local Caddy (verifica cadeia e hostname)"
    )
    parser.add_argument(
        "--insecure-local", action="store_true",
        help="Apenas diagnostico: ignora a autenticidade do certificado local"
    )
    args = parser.parse_args()
    if args.ca_file and args.insecure_local:
        parser.error("--ca-file e --insecure-local sao mutuamente exclusivos")

    if args.insecure_local:
        print("ATENCAO: verificacao do certificado DESATIVADA neste diagnostico local.")
        context = ssl._create_unverified_context()
    elif args.ca_file:
        if not args.ca_file.is_file():
            parser.error(f"Arquivo CA inexistente: {args.ca_file}")
        context = ssl.create_default_context(cafile=str(args.ca_file))
        print(f"[INFO] Validando certificado e hostname via CA: {args.ca_file}")
    else:
        context = ssl.create_default_context()
        print("[INFO] Validando certificado e hostname via trust store padrao")

    try:
        scenarios = [
            ("/", 200),
            ("/health", 200),
            ("/metrics", 403),
            ("/pagina-inexistente", 404),
        ]
        for path, expected_status in scenarios:
            status, body, negotiated, headers = request(path, context)
            assert status == expected_status, f"{path}: HTTP {status}, esperado {expected_status}"
            assert negotiated == "TLSv1.3", f"{path}: TLS negociado {negotiated}, esperado TLSv1.3"
            if path == "/health":
                assert body == b"ok\n", f"Corpo /health incorreto: {body!r}"
            check_headers(headers, path)
            print(f"[OK] HTTPS {path} -> {status}; {negotiated}")
        print("[OK] Refinamento Fase 4: TLS e headers validados.")
    except (OSError, ssl.SSLError, AssertionError) as error:
        print(f"[FALHOU] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
