#!/usr/bin/env python3
"""Teste TLS de Caddy local (requer Caddy e backend ja executando).

Padrao: verifica certificado usando CA do sistema.
Opcao --insecure-local SOMENTE para testes locais com CA do Caddy nao confiada.
"""
import argparse
import http.client
import ssl
import sys


def https_get(path, context):
    conn = http.client.HTTPSConnection("localhost", 8443, context=context, timeout=8)
    try:
        conn.connect()
        negotiated = conn.sock.version()
        conn.request("GET", path)
        response = conn.getresponse()
        body = response.read()
        return response.status, body, negotiated
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--insecure-local", action="store_true", help="Ignora validacao do certificado apenas no laboratorio local")
    args = parser.parse_args()
    if args.insecure_local:
        print("ATENCAO: validacao de certificado desativada APENAS neste teste localhost.")
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context()
    try:
        status, body, tls = https_get("/health", context)
        assert status == 200 and body == b"ok\n", (status, body)
        print(f"[OK] HTTPS /health -> 200; TLS negociado: {tls}")
        status, _body, _ = https_get("/metrics", context)
        assert status == 403, status
        print("[OK] HTTPS /metrics -> 403 (bloqueado pelo proxy)")
        status, _body, _ = https_get("/pagina-inexistente", context)
        assert status == 404, status
        print("[OK] HTTPS /pagina-inexistente -> 404")
    except (OSError, ssl.SSLError, AssertionError) as exc:
        print(f"[FALHOU] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
