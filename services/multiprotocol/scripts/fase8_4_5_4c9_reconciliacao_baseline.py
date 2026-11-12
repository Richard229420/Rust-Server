#!/usr/bin/env python3
"""C.9 — testemunho versionado da transicao de baseline C.2, SEM corte MQTT.

Verifica o snapshot historico e o snapshot pos-PKI-v2; exige diferenca
exclusiva nos 3 arquivos TLS conhecidos; preserva C4/C6/C7/C8 e grava
somente um testemunho privado independente, sem transportar aprovacoes.

Nao migra, reescreve ou revalida automaticamente indices C4/C6/C7/C8.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

OLD_DEFAULT = Path.home() / "server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
NEW_DEFAULT = Path.home() / "server_backups/fase8_4_5_2/snapshot-20261110T192516Z-59cf28e102d1"
PRIVATE_DEFAULT = Path.home() / ".config/rust-server"
STATE_DEFAULT = PRIVATE_DEFAULT / "phase8-4-5-4c/reconciliacao-baseline-c9.json"
PKI_DEFAULT = PRIVATE_DEFAULT / "renovacao-mqtt-staging/ca-v2-20261108T141545Z-ESO7Uc"
EXPECTED = frozenset(("lab/pki/ca.crt", "lab/pki/server.crt", "lab/pki/server.key"))
FILES = {
    "c4": "classificacao-clientes-c4.json",
    "c6": "evidencias-operacionais-c6.json",
    "c7": "coleta-passiva-c7.json",
    "c8": "evidencias-cv1-c8.json",
}
SCHEMA = "rust-server/phase8.4.5.4-c9/baseline-reconciliation-v1"
HEX = re.compile(r"^[a-f0-9]{64}$")
REQ_COUNT = 21

class Block(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Block(message)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def private_file(path: Path, *, max_bytes: int = 2_000_000) -> bytes:
    require(not path.is_symlink(), "arquivo privado com symlink")
    s = path.stat()
    require(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and
            stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1 and
            s.st_size <= max_bytes, "arquivo privado ausente, excessivo ou inseguro")
    return path.read_bytes()


def private_dir(path: Path) -> None:
    require(not path.is_symlink(), "diretorio de estado symlink")
    s = path.stat()
    require(stat.S_ISDIR(s.st_mode) and s.st_uid == os.getuid() and
            stat.S_IMODE(s.st_mode) == 0o700,
            "diretorio de estado nao pertence ao usuario ou nao esta em 0700")


def staging_artifact(path: Path, *, key: bool = False, max_bytes: int = 2_000_000) -> bytes:
    """Leitura somente leitura da PKI v2, com politicas distintas para CRT e KEY.

    Certificados publicos podem estar em 0600, 0640 ou 0644; a chave
    privada do servidor deve permanecer exclusivamente em 0600.
    Rejeita links, dono inesperado, arquivo nao regular e escrita externa.
    """
    require(path.name in ("ca.crt", "server.crt", "server.key"),
            "artefato de staging inesperado")
    require(key == (path.name == "server.key"),
            f"classe de arquivo incorreta: {path.name}")
    require(not path.is_symlink(), f"symlink proibido: {path.name}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        raise Block(f"staging indisponivel ou symlink: {path.name}") from None
    with os.fdopen(fd, "rb") as fh:
        info = os.fstat(fh.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and
                info.st_nlink == 1 and 0 < info.st_size <= max_bytes,
                f"tipo/dono/links/tamanho inseguro: {path.name}")
        perms = stat.S_IMODE(info.st_mode)
        if key:
            require(perms == 0o600, "chave privada server.key precisa estar em 0600")
        else:
            require(perms in (0o600, 0o640, 0o644),
                    f"permissao de certificado {path.name} fora de 0600/0640/0644")
        payload = fh.read(max_bytes + 1)
        require(0 < len(payload) <= max_bytes, f"conteudo vazio/excessivo: {path.name}")
        return payload


def staging_dir_check(path: Path) -> None:
    require(path.absolute() == PKI_DEFAULT and not path.is_symlink(),
            "diretorio staging nao corresponde a PKI v2 homologada")
    private_dir(path)


def embedded_string(data, value: str) -> bool:
    """Conferir impressao em C4 sem assumir estrutura interna nao fornecida."""
    if isinstance(data, dict):
        return any(embedded_string(v, value) for v in data.values())
    if isinstance(data, list):
        return any(embedded_string(v, value) for v in data)
    return isinstance(data, str) and data == value


def verify_metadata(raw_by_stage: dict[str, bytes], old_fingerprint: str,
                    old_snapshot: Path) -> dict[str, str]:
    """Checa vinculos historicos exatos; C8 nunca pode ser promovido a aprovacao."""
    docs = {}
    for label, raw in raw_by_stage.items():
        try:
            docs[label] = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            raise Block(f"indice historico {label.upper()} malformado") from None
        require(isinstance(docs[label], dict), f"indice {label.upper()} nao e objeto JSON")

    require(embedded_string(docs["c4"], old_fingerprint),
            "C4 nao referencia o fingerprint historico")
    for label in ("c6", "c7"):
        require(docs[label].get("snapshot_manifest_sha256") == old_fingerprint,
                f"{label.upper()} nao esta vinculado ao manifesto historico")

    c8 = docs["c8"]
    b = c8.get("baseline")
    require(isinstance(b, dict), "C8 sem baseline historico")
    require(b.get("snapshot") == str(old_snapshot) and
            b.get("c7_sha256") == sha(raw_by_stage["c7"]) and
            b.get("c7_path") == str(STATE_DEFAULT.parent / FILES["c7"]),
            "C8 nao referencia corretamente o C7 e o snapshot historicos")
    require(c8.get("schema") == "rust-server/phase8.4.5.4-c8/evidence-index-v1" and
            c8.get("scenario") == "A" and
            c8.get("approval") == "NOT_GRANTED" and
            c8.get("cutover_8883") == "FORBIDDEN" and
            isinstance(c8.get("requirements"), list) and
            len(c8["requirements"]) == REQ_COUNT and
            len(set(c8["requirements"])) == REQ_COUNT and
            isinstance(c8.get("evidence"), list),
            "gates C8 inesperados ou pendencias nao preservadas")
    require("device-sensor01" not in json.dumps(c8.get("requirements")),
            "identidade revogada no conjunto de pendencias")
    return {label: sha(raw) for label, raw in raw_by_stage.items()}


def changed_labels(old: dict[str, bytes], new: dict[str, bytes]) -> set[str]:
    require(set(old) == set(new) and len(old) == 20,
            "inventario historico e atual nao possuem os mesmos 20 arquivos")
    different = {k for k in old if old[k] != new[k]}
    require(different == EXPECTED,
            "divergencias fora dos tres certificados/chaves esperados da PKI v2")
    return different


def verified_sources(args) -> dict:
    """Chama somente rotinas de leitura C2/C3; nunca executa ensaios MQTT."""
    try:
        phase2 = importlib.import_module("fase8_4_5_2_preparar")
        phase3 = importlib.import_module("fase8_4_5_3_ensaio")
    except (ImportError, OSError):
        raise Block("controladores originais C2/C3 indisponiveis") from None
    project = args.project.resolve(strict=True)
    priv = args.private.resolve(strict=True)
    old = args.old.absolute()
    new = args.new.absolute()
    backups = Path.home() / "server_backups/fase8_4_5_2"
    require(os.geteuid() != 0, "execucao como root proibida")
    require(project == SCRIPT_DIR.parent and priv == PRIVATE_DEFAULT and
            old == OLD_DEFAULT and new == NEW_DEFAULT and old != new and
            old.parent == backups and new.parent == backups,
            "caminhos fora da linha de base homologada; revisar manualmente")
    require(not old.is_symlink() and not new.is_symlink(), "snapshot symlink recusado")
    plugin = args.plugin.absolute()
    require(not plugin.is_symlink() and plugin.is_file(), "plugin DynSec indisponivel")
    try:
        for target in (old, new):
            phase2.verify(target, plugin)
        phase3.assert_origins_match(new, project, priv)
        labels = phase2.sources(project, priv)
        older = {k: phase2.check_regular(old / "files" / k, private=True) for k in labels}
        newer = {k: phase2.check_regular(new / "files" / k, private=True) for k in labels}
        changed_labels(older, newer)
        staging_dir_check(args.staging)
        for f in ("ca.crt", "server.crt", "server.key"):
            current = staging_artifact(args.staging / f, key=(f == "server.key"))
            require(newer["lab/pki/" + f] == current,
                    f"PKI v2 diverge do staging homologado: {f}")
    except Block:
        raise
    except Exception as err:
        raise Block(f"C2/C3 falhou na leitura ou consistencia ({type(err).__name__})") from None
    return {
        "historic_manifest_sha256": sha(private_file(old / phase2.NAME)),
        "current_manifest_sha256": sha(private_file(new / phase2.NAME)),
    }


def evidence_hashes(args, old_fingerprint: str) -> dict[str, str]:
    private_dir(args.state.parent)
    raw_by_stage = {}
    for label, name in FILES.items():
        raw_by_stage[label] = private_file(args.state.parent / name)
    return verify_metadata(raw_by_stage, old_fingerprint, args.old)


def audit(args) -> dict:
    fp = verified_sources(args)
    require(fp["historic_manifest_sha256"] != fp["current_manifest_sha256"],
            "manifestos de baseline identicos; transicao nao demonstrada")
    fp["index_sha256"] = evidence_hashes(args, fp["historic_manifest_sha256"])
    return fp


def make_record(args, result: dict) -> dict:
    return {
        "schema": SCHEMA,
        "created_utc": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "historic_snapshot": str(args.old),
        "current_snapshot": str(args.new),
        "historic_manifest_sha256": result["historic_manifest_sha256"],
        "current_manifest_sha256": result["current_manifest_sha256"],
        "allowed_changed_labels": sorted(EXPECTED),
        "historic_indices_sha256": result["index_sha256"],
        "evidence_count_migrated": 0,
        "c_v1_pending": 21,
        "revalidation_c4_c6_c7_c8": "PENDING_VERSIONED_RECORDS",
        "review": "pending-independent-review",
        "approval": "NOT_GRANTED",
        "cutover_8883": "FORBIDDEN",
    }


def validate_record(data: dict, args, audit_result: dict) -> None:
    require(isinstance(data, dict) and set(data) == set(make_record(args, audit_result)),
            "estrutura de registro C9 alterada")
    expected = make_record(args, audit_result)
    for key, value in expected.items():
        if key != "created_utc":
            require(data[key] == value, f"registro C9 diverge: {key}")
    require(isinstance(data["created_utc"], str) and "+00:00" in data["created_utc"],
            "data de reconciliacao invalida")


def create_exclusive(path: Path, obj: dict) -> None:
    private_dir(path.parent)
    require(not path.exists() and not path.is_symlink(),
            "registro C9 ja existe; nao sobrescrever")
    fd, temp = tempfile.mkstemp(prefix=".c9-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            json.dump(obj, f, ensure_ascii=False, indent=2, sort_keys=True)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.link(temp, path)
        os.unlink(temp)
        dirfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("action", choices=("preflight", "iniciar", "verificar"))
    p.add_argument("--project", type=Path, default=SCRIPT_DIR.parent)
    p.add_argument("--private", type=Path, default=PRIVATE_DEFAULT)
    p.add_argument("--old", type=Path, default=OLD_DEFAULT)
    p.add_argument("--new", type=Path, default=NEW_DEFAULT)
    p.add_argument("--staging", type=Path, default=PKI_DEFAULT)
    p.add_argument("--state", type=Path, default=STATE_DEFAULT)
    p.add_argument("--plugin", type=Path, default=Path("/usr/lib/mosquitto_dynamic_security.so"))
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        require(args.state.absolute() == STATE_DEFAULT,
                "destino de testemunho alterado; nao sobrescrever registros externos")
        result = audit(args)
        if args.action == "preflight":
            print("APROVADO: snapshots historico e pos-PKI-v2 integros; origens atuais consistentes.")
            print("APROVADO: somente 3 arquivos TLS diferem entre 20 fontes.")
            print("APROVADO: indices historicos C4/C6/C7/C8 vinculados e preservados.")
            print("PENDENTE: revisao independente; nenhum indice migrado e nenhuma baixa C-V1.")
        elif args.action == "iniciar":
            create_exclusive(args.state, make_record(args, result))
            print("APROVADO: testemunho C9 privado criado (0600), somente referencia e hashes.")
            print("PENDENTE: revalidacao versionada C4/C6/C7/C8, 21 evidencias e aprovacao externa.")
        else:
            obj = json.loads(private_file(args.state))
            validate_record(obj, args, result)
            print("APROVADO: testemunho C9 integro; indices historicos sem alteracoes.")
            print("PENDENTE: C4/C6/C7/C8 ainda vinculados ao snapshot historico.")
        print("C-V1: 21 abertas; corte 8883 NAO AUTORIZADO.")
        return 0
    except (Block, OSError, ValueError, KeyError, TypeError) as exc:
        # Nao exibe valores vindos de fontes privadas.
        print("BLOQUEADO: " + (str(exc) if isinstance(exc, Block) else type(exc).__name__), file=sys.stderr)
        print("NENHUM CORTE OU MIGRACAO AUTOMATICA REALIZADOS.", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
