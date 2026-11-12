#!/usr/bin/env python3
"""BRI ciclo: broker MQTT 8901 efemero, TLS local, reconexao e rotacao/rollback.

Sem sudo, sem alterar src/, 8883, 8884, PKI real ou indices C.9/C.10.
Logs/segredos em tempdir 0700; nenhum segredo em argumentos do processo.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

PORT = 8901
ROOT = Path(__file__).resolve().parents[1]
TEST_NAME = "bridge_fase8_4_bri_ciclo"


def call(*cmd: str, timeout: int = 40) -> None:
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                   stderr=subprocess.PIPE, timeout=timeout)


def private_file(path: Path, content: str) -> None:
    # Only used in our own fresh private temporary directory.
    with path.open("w", encoding="utf-8") as f:
        f.write(content)
    path.chmod(0o600)


def port_free() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", PORT))


def preflight() -> None:
    if os.geteuid() == 0:
        raise RuntimeError("nao executar como root")
    expected = ROOT / "tests" / (TEST_NAME + ".rs")
    if not expected.is_file() or expected.is_symlink():
        raise RuntimeError("teste Rust isolado ausente")
    for cmd in ("cargo", "mosquitto", "mosquitto_passwd", "openssl"):
        if not shutil.which(cmd):
            raise RuntimeError("ferramenta necessaria ausente: " + cmd)
    port_free()


def compile_test() -> Path:
    proc = subprocess.run(
        ["cargo", "test", "--offline", "--locked", "--test", TEST_NAME,
         "--no-run", "--message-format=json"],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    if proc.returncode:
        raise RuntimeError("compilacao do teste Rust falhou; revisar Cargo local")
    for line in proc.stdout.splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("reason") == "compiler-artifact":
            target = obj.get("target") or {}
            path = obj.get("executable")
            if target.get("name") == TEST_NAME and path and "test" in target.get("kind", []):
                exe = Path(path).resolve(strict=True)
                if not exe.is_file():
                    break
                return exe
    raise RuntimeError("Cargo nao retornou executavel de testes")


def make_pki(tmp: Path) -> None:
    call("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
         "-subj", "/CN=BRI CYCLE Ephemeral CA",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", str(tmp / "ca.key"), "-out", str(tmp / "ca.crt"))
    call("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
         "-subj", "/CN=localhost", "-keyout", str(tmp / "server.key"),
         "-out", str(tmp / "server.csr"))
    private_file(tmp / "server.ext", "basicConstraints=critical,CA:FALSE\n"
                 "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
                 "extendedKeyUsage=serverAuth\n"
                 "keyUsage=digitalSignature,keyEncipherment\n")
    call("openssl", "x509", "-req", "-days", "1", "-sha256",
         "-in", str(tmp / "server.csr"), "-CA", str(tmp / "ca.crt"),
         "-CAkey", str(tmp / "ca.key"), "-CAcreateserial",
         "-extfile", str(tmp / "server.ext"), "-out", str(tmp / "server.crt"))
    for name in ("ca.key", "server.key"):
        (tmp / name).chmod(0o600)


def passwords(tmp: Path, bridge_pw: str, injector_pw: str) -> None:
    private_file(tmp / "passwords", f"bridge:{bridge_pw}\ninjector:{injector_pw}\n")
    # -U hashes the ephemeral plaintext file once, while broker is stopped.
    call("mosquitto_passwd", "-U", str(tmp / "passwords"))
    (tmp / "passwords").chmod(0o600)


def config(tmp: Path) -> None:
    private_file(tmp / "acl", "user bridge\n"
                 "topic read lab/alerts\ntopic read lab/sensors/#\n"
                 "topic write bus/alerts\n"
                 "user injector\ntopic write lab/alerts\n")
    private_file(tmp / "mosquitto.conf", f"listener {PORT} 127.0.0.1\n"
                 "allow_anonymous false\npersistence false\n"
                 f"password_file {tmp / 'passwords'}\nacl_file {tmp / 'acl'}\n"
                 f"certfile {tmp / 'server.crt'}\nkeyfile {tmp / 'server.key'}\n"
                 f"log_dest file {tmp / 'broker.log'}\nlog_type error\nlog_type warning\nlog_type notice\n")


def wait_broker(proc: subprocess.Popen[bytes]) -> None:
    for _ in range(60):
        if proc.poll() is not None:
            raise RuntimeError("broker descartavel finalizou precocemente")
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.15):
                return
        except OSError:
            time.sleep(0.1)
    raise RuntimeError("broker temporario nao abriu porta 8901")


def kill_owned(proc: subprocess.Popen[bytes] | None, timeout: int = 5) -> None:
    if proc is not None and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=timeout)


class Lab:
    def __init__(self, tmp: Path, executable: Path):
        self.tmp = tmp
        self.exe = executable
        self.broker: subprocess.Popen[bytes] | None = None
        self.bridge: subprocess.Popen[bytes] | None = None
        self.run_num = 0
        self.progress: Path | None = None
        self.stop: Path | None = None
        self.old_pw = secrets.token_hex(24)
        self.new_pw = secrets.token_hex(24)
        self.injector_pw = secrets.token_hex(24)
        self.nonce = secrets.token_hex(8)
        private_file(tmp / "old.pw", self.old_pw)
        private_file(tmp / "new.pw", self.new_pw)
        private_file(tmp / "injector.pw", self.injector_pw)

    def env(self, mode: str, bridge_pw: str, marker: str = "") -> dict[str, str]:
        # Do not pass unrelated shell credentials to the isolated Rust process.
        value = {key: os.environ[key] for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ")
                 if key in os.environ}
        value.update({
            "BRI_LAB_MODE": mode, "BRI_LAB_PORT": str(PORT),
            "BRI_LAB_CA": str(self.tmp / "ca.crt"),
            "BRI_LAB_BRIDGE_PWFILE": str(self.tmp / bridge_pw),
            "BRI_LAB_INJECTOR_PWFILE": str(self.tmp / "injector.pw"),
            "BRI_LAB_MARKER": marker,
        })
        if mode == "bridge":
            assert self.progress is not None and self.stop is not None
            value.update({
                "BRI_LAB_PROGRESS": str(self.progress),
                "BRI_LAB_READY": str(self.tmp / f"ready-{self.run_num}"),
                "BRI_LAB_STOP": str(self.stop),
            })
        return value

    def execute(self, mode: str, bridge_pw: str, marker: str = "") -> None:
        result = subprocess.run(
            [str(self.exe), "--ignored", "--exact", "lifecycle_bri", "--test-threads=1"],
            cwd=ROOT, env=self.env(mode, bridge_pw, marker),
            capture_output=True, timeout=18,
        )
        if result.returncode != 0:
            raise RuntimeError("teste isolado reprovado: " + mode)

    def start_broker(self) -> None:
        if self.broker is not None:
            raise RuntimeError("broker duplicado")
        with (self.tmp / "broker.stdout").open("ab") as out, \
             (self.tmp / "broker.stderr").open("ab") as err:
            self.broker = subprocess.Popen(
                ["mosquitto", "-c", str(self.tmp / "mosquitto.conf")],
                cwd=self.tmp, stdout=out, stderr=err,
            )
        wait_broker(self.broker)

    def stop_broker(self) -> None:
        kill_owned(self.broker)
        self.broker = None

    def start_bridge(self, bridge_pw: str) -> None:
        if self.bridge is not None:
            raise RuntimeError("bridge de teste duplicada")
        self.run_num += 1
        self.progress = self.tmp / f"progress-{self.run_num}"
        self.stop = self.tmp / f"stop-{self.run_num}"
        private_file(self.progress, "")
        with (self.tmp / f"bridge-{self.run_num}.stdout").open("wb") as out, \
             (self.tmp / f"bridge-{self.run_num}.stderr").open("wb") as err:
            self.bridge = subprocess.Popen(
                [str(self.exe), "--ignored", "--exact", "lifecycle_bri", "--test-threads=1"],
                cwd=ROOT, env=self.env("bridge", bridge_pw), stdout=out, stderr=err,
            )
        ready = self.tmp / f"ready-{self.run_num}"
        for _ in range(80):
            if self.bridge.poll() is not None:
                raise RuntimeError("bridge efemera terminou antes do ensaio")
            if ready.is_file():
                return
            time.sleep(0.1)
        raise RuntimeError("bridge nao iniciou threads no prazo")

    def stop_bridge(self) -> None:
        if self.bridge is not None and self.bridge.poll() is None and self.stop is not None:
            private_file(self.stop, "stop")
            try:
                self.bridge.wait(timeout=5)
            except subprocess.TimeoutExpired:
                kill_owned(self.bridge)
        if self.bridge is not None and self.bridge.returncode not in (0, None):
            raise RuntimeError("bridge efemera terminou com falha")
        self.bridge = None

    def marker(self, stage: str) -> str:
        return f"BRI_TEST_{self.nonce}_{stage}"

    def observed(self, marker: str) -> bool:
        return bool(self.progress is not None and self.progress.is_file()
                    and marker in self.progress.read_text(encoding="utf-8").splitlines())

    def delivery(self, stage: str) -> None:
        if self.bridge is None or self.progress is None:
            raise RuntimeError("bridge nao esta em execucao")
        marker = self.marker(stage)
        for _ in range(12):
            if self.bridge.poll() is not None:
                raise RuntimeError("bridge caiu antes da entrega")
            self.execute("publish", "old.pw", marker)
            if self.observed(marker):
                return
            time.sleep(0.45)
        raise RuntimeError("mensagem nao passou pela bridge: " + stage)

    def cleanup(self) -> None:
        if self.bridge is not None:
            try:
                self.stop_bridge()
            except RuntimeError:
                kill_owned(self.bridge)
                self.bridge = None
        self.stop_broker()


def main() -> int:
    os.umask(0o077)
    preflight()
    print("APROVADO: ferramentas presentes e 127.0.0.1:8901 livre.", flush=True)
    exe = compile_test()
    print("APROVADO: harness Rust isolado compilado (cargo offline/locked).", flush=True)
    with tempfile.TemporaryDirectory(prefix="rust-bri-ciclo-") as t:
        tmp = Path(t)
        tmp.chmod(0o700)
        lab = Lab(tmp, exe)
        try:
            make_pki(tmp)
            config(tmp)
            passwords(tmp, lab.old_pw, lab.injector_pw)
            lab.start_broker()
            lab.start_bridge("old.pw")
            lab.delivery("INICIAL")
            print("APROVADO: bridge real conectou com senha A e entregou lab/alerts ao bus adaptado.", flush=True)

            lab.stop_broker()
            lab.start_broker()
            lab.delivery("RECONEXAO")
            print("APROVADO: mesma instancia de bridge reconectou apos reinicio do broker.", flush=True)

            lab.stop_broker()
            passwords(tmp, lab.new_pw, lab.injector_pw)
            lab.start_broker()
            lab.execute("reject", "old.pw")
            lab.execute("accept", "new.pw")
            if lab.bridge is None or lab.bridge.poll() is not None:
                raise RuntimeError("bridge original nao permaneceu ativa durante rotacao")
            # A senha A armazenada na memoria da bridge nao e recarregada automaticamente.
            marker = lab.marker("APOS_ROTACAO_SEM_RESTART")
            lab.execute("publish", "new.pw", marker)
            time.sleep(1.5)
            if lab.observed(marker):
                raise RuntimeError("bridge antiga recebeu mensagem apos credencial revogada")
            print("APROVADO: senha A recusada e senha B aceita; bridge antiga nao recebeu apos rotacao.", flush=True)

            lab.stop_bridge()
            lab.start_bridge("new.pw")
            lab.delivery("ROTACIONADA")
            print("APROVADO: bridge reiniciada com senha B e nova sessao TLS entregou mensagem.", flush=True)

            lab.stop_bridge()
            lab.stop_broker()
            passwords(tmp, lab.old_pw, lab.injector_pw)
            lab.start_broker()
            lab.execute("reject", "new.pw")
            lab.execute("accept", "old.pw")
            lab.start_bridge("old.pw")
            lab.delivery("ROLLBACK")
            print("APROVADO: rollback para senha A e reconexao da bridge reiniciada.", flush=True)
            print("LIMITES: bus adaptado; broker B; rotacao exige reinicio do cliente; sem cenario A.")
            print("C-V1: 21 abertas; C9/C10 inalteradas; sem corte 8883 e sem alteracao 8884.")
            return 0
        finally:
            lab.cleanup()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        # Never display command arguments, private paths, credentials or raw logs.
        print("BLOQUEADO: " + type(exc).__name__ + "; verifique logs locais efemeros sem compartilhá-los.",
              file=sys.stderr)
        sys.exit(2)
