#!/usr/bin/env python3
"""Ensaio negativo BRI em 8901: autenticacao, CA TLS e ACL SUBACK.

Usa o controlador positivo anterior para fabricar a PKI/configuracao temporaria,
mas NAO executa a bridge nem a aplicacao completa. Nenhum dado operacional.
"""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import testar_bridge_bri_8901 as base

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "tests/bridge_fase8_4_bri_negativos.rs"
CASES = ("auth_rejeitada", "ca_nao_confiavel", "acl_subscribe_negada")


def make_bad_ca(tmp: Path) -> None:
    # CA independente (testa validacao de cadeia, nao resolucao DNS).
    base.call("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
              "-days", "1", "-subj", "/CN=BRI Bad CA Do Not Trust",
              "-addext", "basicConstraints=critical,CA:TRUE",
              "-addext", "keyUsage=critical,keyCertSign,cRLSign",
              "-keyout", str(tmp / "bad-ca.key"), "-out", str(tmp / "bad-ca.crt"))
    (tmp / "bad-ca.key").chmod(0o600)


def main() -> int:
    old_mask = os.umask(0o077)
    try:
        base.preflight()
        if not TEST.is_file() or TEST.is_symlink():
            raise RuntimeError("teste negativo Rust ausente ou inseguro")
        with tempfile.TemporaryDirectory(prefix="rust-bri-neg-8901-") as folder:
            tmp = Path(folder)
            tmp.chmod(0o700)
            base.make_pki(tmp)
            base.make_mosquitto_config(tmp)
            make_bad_ca(tmp)
            proc = None
            try:
                with (tmp/"mosquitto.stdout").open("wb") as out, (tmp/"mosquitto.stderr").open("wb") as err:
                    proc = subprocess.Popen(("mosquitto", "-c", str(tmp/"mosquitto.conf")),
                                            stdout=out, stderr=err, cwd=tmp)
                    base.wait_broker(proc)
                    print("APROVADO: broker 8901 isolado com TLS e ACL de teste.", flush=True)
                    env = os.environ.copy()
                    env.update({
                        "BRI_LAB_PORT": "8901", "BRI_LAB_CA": str(tmp/"ca.crt"),
                        "BRI_LAB_BAD_CA": str(tmp/"bad-ca.crt"),
                        "BRI_LAB_BRIDGE_PWFILE": str(tmp/"bridge.pw"),
                        "BRI_LAB_INJECTOR_PWFILE": str(tmp/"injector.pw"),
                    })
                    for case in CASES:
                        result = subprocess.run((
                            "cargo", "test", "--offline", "--locked", "--test",
                            "bridge_fase8_4_bri_negativos", case, "--",
                            "--ignored", "--exact", "--test-threads=1"),
                            cwd=ROOT, env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=60)
                        if result.returncode != 0 or "1 passed" not in result.stdout:
                            # Nao exibir saida bruta contendo dados de laboratorio.
                            raise RuntimeError(f"teste {case} reprovado; reveja saidas localmente")
                        print(f"APROVADO: {case}", flush=True)
                    print("LIMITES: broker B, sem bridge em runtime, sem rotacao/rollback e sem prova do cenario A.")
                    print("C-V1: 21 pendencias abertas; 8883/8884 intocados; C10 nao modificado.")
                    return 0
            finally:
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
    finally:
        os.umask(old_mask)

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired) as e:
        print(f"BLOQUEADO: {type(e).__name__}; verifique localmente. Nenhuma autorizacao de corte.",
              file=sys.stderr)
        sys.exit(2)
