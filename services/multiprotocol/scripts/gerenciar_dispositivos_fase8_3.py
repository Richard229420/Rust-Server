#!/usr/bin/env python3
"""Fase 8.3: provisionamento offline de credenciais MQTT por dispositivo.

Somente stdlib; não recebe senhas em argumentos, não chama mosquitto_passwd -b.
O broker deve estar PARADO para alterações. Na próxima inicialização, todas
as sessões anteriores estarão encerradas (SIGHUP isolado não revoga sessões).
"""
from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile

MAX_DEVICES = 32
ID_RE = re.compile(r"[a-z][a-z0-9-]{2,31}\Z")
LEGACY_BASE_RULES = [
    "user bridge",
    "topic read lab/alerts",
    "topic read lab/sensors/#",
    "topic write bus/alerts",
    "topic write bus/sensors/#",
    "user lab",
    "topic write lab/alerts",
    "topic write lab/sensors/#",
    "topic read bus/alerts",
    "topic read bus/sensors/#",
]
# A conta compartilhada lab conserva apenas alertas. A autorizacao por
# dispositivo passa a ser exclusiva das contas device-<ID>.
HARDENED_BASE_RULES = [
    "user bridge",
    "topic read lab/alerts",
    "topic read lab/sensors/#",
    "topic write bus/alerts",
    "topic write bus/sensors/#",
    "user lab",
    "topic write lab/alerts",
    "topic read bus/alerts",
]

BEGIN = "# BEGIN FASE8.3 DEVICES (gerado; nao editar)"
END = "# END FASE8.3 DEVICES"

class Fail(Exception):
    pass

def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")

def valid_id(raw: str) -> str:
    if not ID_RE.fullmatch(raw) or "--" in raw or raw.endswith("-"):
        raise Fail("ID invalido: use 3-32 caracteres [a-z0-9-], iniciando com letra; sem '--' nem '-' final")
    return raw

def secure_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise Fail(f"Diretorio inseguro: {path}")
    if (path.stat().st_mode & 0o077) != 0:
        raise Fail(f"Diretorio permite acesso a outros usuarios: {path} (use chmod 700)")

def check_safe_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise Fail(f"Arquivo ausente ou link simbolico nao permitido: {path}")
    if (path.stat().st_mode & 0o077) != 0:
        raise Fail(f"Arquivo {path} nao e privado (chmod 600)")

def atomic_write(path: Path, data: str, mode: int = 0o600) -> None:
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)

def offline() -> None:
    for host in ("127.0.0.1",):
        try:
            with socket.create_connection((host, 8883), timeout=0.3):
                raise Fail("Broker MQTT ativo em 127.0.0.1:8883: interrompa o Terminal B (Ctrl+C) antes de alterar contas")
        except (OSError, TimeoutError):
            pass

def parse_base(acl: str) -> str:
    if BEGIN in acl:
        base, rest = acl.split(BEGIN, 1)
        if END not in rest:
            raise Fail("Marcador de ACL incompleto; nao e seguro sobrescrever")
        if rest.split(END, 1)[1].strip():
            raise Fail("Regras adicionais depois do marcador gerenciado; revise manualmente")
    else:
        base = acl
    rules = [x.strip() for x in base.splitlines() if x.strip() and not x.strip().startswith("#")]
    if rules not in (LEGACY_BASE_RULES, HARDENED_BASE_RULES):
        raise Fail("ACL base nao corresponde a Fase 8.2/8.3; revisar regras antes de automatizar")
    # Retira de lab os direitos globais sobre sensores, sem alterar a conta bridge.
    # Ao salvar, o estado passa a ser o baseline restrito e idempotente.
    return "# ACL base Fase 8.3: lab compartilhado somente para alerts\n" + "\n".join(HARDENED_BASE_RULES) + "\n\n"

def acl_text(base: str, devices: dict) -> str:
    out = [base, BEGIN]
    for ident, info in sorted(devices.items()):
        if info["state"] == "active":
            out.extend([
                f"user device-{ident}",
                f"topic write lab/sensors/{ident}/#",
                f"topic read bus/sensors/{ident}/#",
                "",
            ])
    out.append(END)
    return "\n".join(out) + "\n"

def validate_accounts(passwords: str) -> list[str]:
    lines = [s for s in passwords.splitlines() if s.strip()]
    users = []
    for line in lines:
        if ":" not in line or ":$" not in line:
            raise Fail("Arquivo passwords nao parece conter apenas hashes; abortando")
        user, _ = line.split(":", 1)
        if user in users or not user:
            raise Fail("Usuario duplicado ou vazio no password_file")
        users.append(user)
    if "bridge" not in users or "lab" not in users:
        raise Fail("Contas base 'bridge' e 'lab' ausentes")
    return lines

def read_state(folder: Path):
    paths = [folder / name for name in ("passwords", "acl", "mosquitto.conf")]
    for p in paths:
        check_safe_file(p)
    passwords, acl, conf = [p.read_text(encoding="utf-8") for p in paths]
    lines = validate_accounts(passwords)
    base = parse_base(acl)
    meta_path = folder / "devices.json"
    if meta_path.exists():
        check_safe_file(meta_path)
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("version") != 1 or not isinstance(meta.get("devices"), dict):
            raise Fail("Formato do inventario devices.json desconhecido")
    else:
        meta = {"version": 1, "devices": {}}
        if any(x.startswith("device-") for x in (line.split(":", 1)[0] for line in lines)):
            raise Fail("Ha contas device- sem inventario; revisar antes de continuar")
    validate_sync(lines, meta["devices"], acl)
    return lines, base, conf, meta

def validate_sync(lines: list[str], devices: dict, acl: str) -> None:
    users = {x.split(":", 1)[0] for x in lines}
    active = {f"device-{i}" for i, v in devices.items() if v.get("state") == "active"}
    for ident, info in devices.items():
        valid_id(ident)
        if info.get("state") not in ("active", "revoked"):
            raise Fail(f"Estado de dispositivo invalido: {ident}")
    if {u for u in users if u.startswith("device-")} != active:
        raise Fail("Inventario e arquivo de senhas divergentes; nao alterar sem reconciliar")
    # ACL precisa corresponder integralmente ao inventario; sem regras avulsas.
    if devices:
        acl_users = set(re.findall(r"^user (device-[a-z0-9-]+)$", acl, flags=re.MULTILINE))
        if acl_users != active:
            raise Fail("Inventario e ACL divergentes")
        current_base = parse_base(acl)
        if acl != acl_text(current_base, devices):
            raise Fail("ACL do dispositivo difere do inventario gerado; nao alterar")

def verify_conf(conf: str, folder: Path) -> None:
    lines = [x.strip() for x in conf.splitlines() if x.strip() and not x.strip().startswith("#")]
    expected = {
        "listener 8883 127.0.0.1",
        "allow_anonymous false",
        f"password_file {folder / 'passwords'}",
        f"acl_file {folder / 'acl'}",
        "tls_version tlsv1.2",
    }
    if not expected.issubset(lines) or not any(x.startswith("certfile ") for x in lines) or not any(x.startswith("keyfile ") for x in lines):
        raise Fail("mosquitto.conf nao corresponde ao listener TLS/ACL da Fase 8.2")
    if any(x.startswith("listener ") and x != "listener 8883 127.0.0.1" for x in lines):
        raise Fail("Listener adicional identificado; nao alterar automaticamente")

def harden_conf(conf: str) -> str:
    specs = {"max_connections": "64", "max_packet_size": "4096", "max_queued_messages": "32", "max_queued_bytes": "32768", "max_inflight_messages": "10", "max_qos": "1"}
    rest = []
    for row in conf.splitlines():
        x = row.strip().split()
        if x and (x[0] == "message_size_limit" or x[0] in specs):
            continue
        rest.append(row)
    rest += ["", "# Fase 8.3: cotas conservadoras (loopback)"]
    rest += [f"{key} {value}" for key, value in specs.items()]
    return "\n".join(rest).rstrip() + "\n"

def hash_password(user: str, secret: str) -> str:
    if not Path("/dev/shm").is_dir():
        raise Fail("/dev/shm nao disponivel; segredo nao sera gravado em disco persistente")
    with tempfile.TemporaryDirectory(prefix="mqtt-dev-", dir="/dev/shm") as temp:
        os.chmod(temp, 0o700)
        tmp = Path(temp) / "plaintext"
        tmp.write_text(f"{user}:{secret}\n", encoding="utf-8")
        tmp.chmod(0o600)
        result = subprocess.run(["mosquitto_passwd", "-U", str(tmp)], capture_output=True, text=True, check=False)
        if result.returncode != 0:
            raise Fail("mosquitto_passwd -U falhou; nenhum arquivo de producao foi alterado")
        lines = tmp.read_text(encoding="utf-8").splitlines()
        if len(lines) != 1 or not lines[0].startswith(user + ":$"):
            raise Fail("A conversao de senha nao retornou um hash esperado")
        return lines[0]

def snapshot(folder: Path, label: str) -> Path:
    root = folder / "backups-fase8-3"
    secure_dir(root)
    target = root / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S-%f") + "-" + label)
    secure_dir(target)
    for name in ("passwords", "acl", "mosquitto.conf", "devices.json"):
        file = folder / name
        if file.exists():
            shutil.copy2(file, target / name)
            os.chmod(target / name, 0o600)
    return target

def save(folder: Path, passwords: list[str], base: str, conf: str, meta: dict, *, label: str, update_conf: bool = False) -> None:
    snap = snapshot(folder, label)
    # Configs nao sao validadas pelo mosquitto neste host: o broker so sobe apos alteracoes.
    atomic_write(folder / "passwords", "\n".join(passwords) + "\n")
    atomic_write(folder / "acl", acl_text(base, meta["devices"]))
    atomic_write(folder / "devices.json", json.dumps(meta, indent=2, sort_keys=True) + "\n")
    if update_conf:
        atomic_write(folder / "mosquitto.conf", harden_conf(conf))
    print(f"Snapshot privado dos arquivos anteriores: {snap}")

def save_token(root: Path, ident: str, password: str) -> Path:
    secure_dir(root)
    dest = root / f"{ident}.token"
    if dest.is_symlink():
        raise Fail(f"Arquivo de credencial e link simbolico: {dest}")
    atomic_write(dest, password + "\n")
    return dest

def main() -> int:
    parser = argparse.ArgumentParser(description="Fase 8.3: usuarios MQTT por sensor (offline)")
    parser.add_argument("--mosquitto-dir", type=Path, default=Path.home() / ".config/rust-server/mosquitto", help=argparse.SUPPRESS)
    subs = parser.add_subparsers(dest="action", required=True)
    subs.add_parser("init", help="Preparar ACL de dispositivos e cotas (broker parado)")
    subs.add_parser("list", help="Listar dispositivos e estados, sem credenciais")
    for action in ("create", "rotate", "revoke"):
        sub = subs.add_parser(action)
        sub.add_argument("device_id", help="ID do sensor, ex: sensor01")
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Fail("Nao execute o gerenciador com sudo/root")
    folder = args.mosquitto_dir.expanduser().resolve()
    secure_dir(folder)
    lock = folder / ".fase83.lock"
    with open(lock, "a+", encoding="utf-8") as handle:
        os.chmod(lock, 0o600)
        fcntl.flock(handle, fcntl.LOCK_EX)
        if args.action != "list":
            offline()
        lines, base, conf, meta = read_state(folder)
        verify_conf(conf, folder)
        devices = meta["devices"]
        if args.action == "list":
            if not devices:
                print("Nenhum dispositivo cadastrado")
            for ident, info in sorted(devices.items()):
                print(f"{ident}\t{info['state']}\trotacoes={info.get('rotations', 0)}\tatualizado={info.get('updated_at', '?')}")
            return 0
        if args.action == "init":
            save(folder, lines, base, conf, meta, label="init", update_conf=True)
            print("Fase 8.3 configurada. Reinicie o Mosquitto APOS alterar contas.")
            return 0
        ident = valid_id(args.device_id)
        user = f"device-{ident}"
        if args.action == "create":
            if ident in devices:
                raise Fail("Identidade existente ou revogada: use outro ID; IDs revogados nao podem ser reutilizados")
            if sum(info["state"] == "active" for info in devices.values()) >= MAX_DEVICES:
                raise Fail(f"Limite de {MAX_DEVICES} dispositivos ativos")
            secret = secrets.token_urlsafe(36)
            new_hash = hash_password(user, secret)
            devices[ident] = {"state": "active", "created_at": now(), "updated_at": now(), "rotations": 0}
            lines.append(new_hash)
        elif args.action == "rotate":
            if ident not in devices or devices[ident]["state"] != "active":
                raise Fail("Somente dispositivos ativos podem ter a credencial rotacionada")
            secret = secrets.token_urlsafe(36)
            new_hash = hash_password(user, secret)
            lines = [x for x in lines if not x.startswith(user + ":")]
            lines.append(new_hash)
            devices[ident]["updated_at"] = now()
            devices[ident]["rotations"] = devices[ident].get("rotations", 0) + 1
        elif args.action == "revoke":
            if ident not in devices or devices[ident]["state"] != "active":
                raise Fail("Identidade nao existe ou ja foi revogada")
            lines = [x for x in lines if not x.startswith(user + ":")]
            devices[ident]["state"] = "revoked"
            devices[ident]["updated_at"] = now()
            devices[ident]["revoked_at"] = now()
        # gerar credencial antes de aplicar o snapshot para evitar gravar estado ativo sem token.
        tokens = folder.parent / "device-tokens"
        if args.action in ("create", "rotate"):
            credential_path = save_token(tokens, ident, secret)
        save(folder, lines, base, conf, meta, label=f"{args.action}-{ident}")
        if args.action == "revoke":
            cred = tokens / f"{ident}.token"
            if cred.exists():
                if cred.is_symlink():
                    raise Fail("Credencial inesperada como symlink; remova manualmente")
                cred.unlink()
        else:
            print(f"Credencial temporaria de entrega: {credential_path} (modo 0600; APAGUE apos provisionar)")
            print(f"Usuario MQTT: {user}")
            print(f"Publicar: lab/sensors/{ident}/# | Assinar: bus/sensors/{ident}/#")
        print("Alteracao registrada com broker PARADO. Inicie novamente o Terminal B para entrar em vigor.")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Fail, OSError, subprocess.SubprocessError, json.JSONDecodeError) as exc:
        print(f"ERRO: {exc}", file=sys.stderr)
        sys.exit(1)
