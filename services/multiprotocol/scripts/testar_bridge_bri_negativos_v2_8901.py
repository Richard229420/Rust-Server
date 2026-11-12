#!/usr/bin/env python3
"""BRI lab negativo v2: 8901 TLS, senha, CA e ACL por entrega real.

Somente broker efemero B. Reutiliza gerador positivo BRI 8901 sem alteracoes.
"""
from __future__ import annotations
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile

import testar_bridge_bri_8901 as base

ROOT = Path(__file__).resolve().parents[1]
TEST = ROOT / "tests/bridge_fase8_4_bri_negativos_v2.rs"
CASES = ("auth_rejeitada", "ca_nao_confiavel", "acl_entrega_negada")


def make_bad_ca(tmp: Path) -> None:
    base.call("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
              "-days", "1", "-subj", "/CN=BRI Bad CA Do Not Trust",
              "-addext", "basicConstraints=critical,CA:TRUE",
              "-addext", "keyUsage=critical,keyCertSign,cRLSign",
              "-keyout", str(tmp / "bad-ca.key"), "-out", str(tmp / "bad-ca.crt"))
    (tmp / "bad-ca.key").chmod(0o600)


def add_auditor(tmp: Path) -> None:
    """Acrescenta usuario *descartavel* com read bus/alerts ao ACL de teste.

    Nunca passa senha em argumentos, nem altera password_file de outros brokers.
    """
    password = secrets.token_hex(24)
    base.write_private(tmp / "auditor.pw", password)
    aux = tmp / "auditor.passwd.tmp"
    base.write_private(aux, f"auditor:{password}\n")
    base.call("mosquitto_passwd", "-U", str(aux))
    with (tmp / "passwords").open("ab") as f:
        f.write(aux.read_bytes())
    aux.unlink()
    with (tmp / "acl").open("a", encoding="utf-8") as f:
        f.write("user auditor\ntopic read bus/alerts\n")


def main() -> int:
    old_mask = os.umask(0o077)
    try:
        base.preflight()
        if not TEST.is_file() or TEST.is_symlink():
            raise RuntimeError("teste Rust v2 ausente ou inseguro")
        with tempfile.TemporaryDirectory(prefix="rust-bri-neg-v2-8901-") as folder:
            tmp = Path(folder)
            tmp.chmod(0o700)
            base.make_pki(tmp)
            base.make_mosquitto_config(tmp)
            add_auditor(tmp)
            make_bad_ca(tmp)
            proc = None
            try:
                with (tmp / "mosquitto.stdout").open("wb") as out, (tmp / "mosquitto.stderr").open("wb") as err:
                    proc = subprocess.Popen(("mosquitto", "-c", str(tmp / "mosquitto.conf")),
                                            stdout=out, stderr=err, cwd=tmp)
                    base.wait_broker(proc)
                    print("APROVADO: Mosquitto TLS descartavel 8901 com auditor ACL.", flush=True)
                    env = os.environ.copy()
                    env.update({
                        "BRI_LAB_PORT": "8901", "BRI_LAB_CA": str(tmp / "ca.crt"),
                        "BRI_LAB_BAD_CA": str(tmp / "bad-ca.crt"),
                        "BRI_LAB_BRIDGE_PWFILE": str(tmp / "bridge.pw"),
                        "BRI_LAB_INJECTOR_PWFILE": str(tmp / "injector.pw"),
                        "BRI_LAB_AUDITOR_PWFILE": str(tmp / "auditor.pw"),
                        "BRI_LAB_NONCE": secrets.token_hex(16),
                    })
                    for case in CASES:
                        try:
                            result = subprocess.run((
                                "cargo", "test", "--offline", "--locked", "--test",
                                "bridge_fase8_4_bri_negativos_v2", case, "--",
                                "--ignored", "--exact", "--test-threads=1"),
                                cwd=ROOT, env=env, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                        except subprocess.TimeoutExpired:
                            print(f"BLOQUEADO: {case}: tempo limite de 60s.", file=sys.stderr)
                            return 2
                        if result.returncode != 0 or "1 passed" not in result.stdout:
                            # Nao imprimir stdout/stderr que possam conter dados de teste.
                            print(f"BLOQUEADO: {case}: assercao ou execucao falhou. "
                                  "Revisar saida no proprio host sem compartilhar credenciais.",
                                  file=sys.stderr)
                            return 2
                        print(f"APROVADO: {case}", flush=True)
                    print("LIMITES: broker B, sem provar implantacao cenario A; nao testa rotacao/rollback.")
                    print("C-V1: 21 abertas; C.10 inalterada; 8883/8884 intocados.")
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
        print(f"BLOQUEADO: preparo do laboratorio ({type(e).__name__}); "
              "nenhum corte autorizado.", file=sys.stderr)
        sys.exit(2)
