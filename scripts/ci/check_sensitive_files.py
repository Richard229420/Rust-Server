#!/usr/bin/env python3
"""Falha se arquivos versionados apresentam sinais de material sigiloso.

Escopo: arvore de arquivos rastreados pelo Git. Nao prova ausencia de segredos
no historico, em arquivos ignorados ou em configuracoes do GitHub.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]

# Falha conservadora por caminho: certificados/credenciais gerados nao vao ao Git.
SENSITIVE_PATHS = [
    re.compile(r"(^|/)\.env(?:$|\.)", re.IGNORECASE),
    re.compile(r"(^|/)\.config/rust-server/", re.IGNORECASE),
    re.compile(r"(^|/)(?:certs|device-tokens|backups-fase8-3)/", re.IGNORECASE),
    re.compile(r"(^|/)(?:env_phase8\.sh|mosquitto\.passwd|passwd|passwords|credentials(?:\.json)?)$", re.IGNORECASE),
    re.compile(r"\.(?:key|p12|pfx|jks|keystore|sqlite|sqlite3|db|db-wal|db-shm)$", re.IGNORECASE),
    re.compile(r"(^|/)(?:id_rsa|id_ecdsa|id_ed25519)$"),
]

PRIVATE_KEY_PATTERN = re.compile(
    rb"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
)
AWS_KEY_PATTERN = re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")

# Exemplos explicitamente documentados podem existir, mas .env real nunca.
ALLOWED_PATHS = {".env.example", "services/multiprotocol/.env.example"}


def main() -> int:
    try:
        completed = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"ERRO: impossivel consultar arquivos do Git: {exc}", file=sys.stderr)
        return 2

    problems: list[str] = []
    for raw_path in filter(None, completed.stdout.split(b"\0")):
        path = raw_path.decode("utf-8", "surrogateescape").replace("\\", "/")
        if path not in ALLOWED_PATHS and any(p.search(path) for p in SENSITIVE_PATHS):
            problems.append(f"{path}: caminho sensivel versionado")

        file_path = ROOT / path
        if not file_path.is_file() or file_path.is_symlink():
            continue
        try:
            with file_path.open("rb") as source:
                content = source.read(6_000_001)
        except OSError:
            problems.append(f"{path}: nao foi possivel inspecionar")
            continue
        if len(content) > 6_000_000:
            continue
        if PRIVATE_KEY_PATTERN.search(content):
            problems.append(f"{path}: bloco de chave privada encontrado")
        if AWS_KEY_PATTERN.search(content):
            problems.append(f"{path}: padrao de credencial de nuvem encontrado")

    if problems:
        print("REPROVADO: revisar antes de push/merge:", file=sys.stderr)
        for problem in sorted(set(problems)):
            print(f"  - {problem}", file=sys.stderr)
        print("Remova do indice e investigue o historico; rotate segredos expostos.", file=sys.stderr)
        return 1

    print("APROVADO: sem caminhos sensiveis ou assinaturas de chave privada nos arquivos rastreados.")
    print("ATENCAO: checagem parcial; ainda e necessaria revisao manual/historica.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
