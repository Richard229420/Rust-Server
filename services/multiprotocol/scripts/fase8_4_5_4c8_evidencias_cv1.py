#!/usr/bin/env python3
"""Rust-Server Fase 8.4.5.4-C.8 — indice privado de evidencias C-V1.

Somente metadados de evidencias do CENARIO A. Nao acessa broker, DynSec,
credenciais, certificados ou Git. Nao fecha pendencias nem autoriza corte.
"""
from __future__ import annotations

import argparse
import contextlib
import importlib.util
import inspect
import io
from collections import Counter
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

STATE_DEFAULT = Path.home() / ".config/rust-server/phase8-4-5-4c/evidencias-cv1-c8.json"
C7_DEFAULT = Path.home() / ".config/rust-server/phase8-4-5-4c/coleta-passiva-c7.json"
SNAPSHOT_DEFAULT = Path.home() / "server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
SCHEMA = "rust-server/phase8.4.5.4-c8/evidence-index-v1"
BRANCH = "feature/fase8-4-inventory-dynsec"

# Exatamente 21 pendencias da avaliacao C-V1 preexistente, sem reinterpretacao
# nem baixa automatica. Ver documentacao C.7 no projeto para a fonte.
REQUIREMENTS = (
    ("LAB-01", "lab", "Client ID real nao registrado", "Comprovar instancias CLI reais e politica de IDs; nao inventar um ID fixo."),
    ("LAB-02", "lab", "Origem do Client ID nao registrada", "Documentar quem gera o ID e o contexto de execucao no cenario A."),
    ("LAB-03", "lab", "Evidencia verificavel pendente", "Registro redigido de uso operacional real; script de laboratorio nao basta."),
    ("LAB-04", "lab", "client_id_confirmado pendente", "Revisao independente da politica de IDs e das instancias reais."),
    ("LAB-05", "lab", "cliente_suporta_troca_credencial pendente", "Ensaio do cliente CLI real em isolamento; sem segredos no indice."),
    ("LAB-06", "lab", "retorno_credencial_legada_planejado pendente", "Plano por operador/instancia para retorno seguro, sem executar corte."),
    ("BRI-01", "bridge", "client_id_confirmado pendente", "Comprovar em runtime do cenario A, nao somente o literal no codigo Rust."),
    ("BRI-02", "bridge", "cliente_suporta_troca_credencial pendente", "Comprovar configuracao, TLS e reautenticacao da bridge real em isolamento."),
    ("BRI-03", "bridge", "retorno_credencial_legada_planejado pendente", "Plano de retorno e reconexao da bridge real, validado fora de producao."),
    ("SNS-01", "device-sensor02", "Client ID real nao registrado", "Inventario autorizado do dispositivo ou servico real; nao inferir do .opts."),
    ("SNS-02", "device-sensor02", "Origem do Client ID nao registrada", "Documentar firmware/host, configuracao e origem do ID no cenario A."),
    ("SNS-03", "device-sensor02", "Evidencia verificavel pendente", "Comprovar implantacao; se ausente, solicitar exclusao formal ao escopo."),
    ("SNS-04", "device-sensor02", "client_id_confirmado pendente", "Conferencia independente do Client ID efetivo do dispositivo real."),
    ("SNS-05", "device-sensor02", "cliente_suporta_troca_credencial pendente", "Ensaio de atualizacao autenticada com firmware/cliente real em isolamento."),
    ("SNS-06", "device-sensor02", "retorno_credencial_legada_planejado pendente", "Plano de retorno do sensor02 real com teste de reconexao."),
    ("OPS-01", "operacionais", "canal_distribuicao_secreta_definido pendente", "Custodiante, cofre e canal autenticado, sem documentar senha ou token."),
    ("OPS-02", "operacionais", "procedimento_rotacao_documentado pendente", "Runbook de rotacao por identidade, responsaveis e retorno."),
    ("OPS-03", "operacionais", "reconfiguracao_cliente_testada_fora_de_producao pendente", "Relatorio dos clientes reais ensaiados em isolamento, nao do broker B apenas."),
    ("OPS-04", "operacionais", "rollback_reconexao_testado_fora_de_producao pendente", "Comprovar reconexao de cada cliente apos retorno em isolamento."),
    ("OPS-05", "operacionais", "janela_e_responsaveis_definidos pendente", "Aprovacoes, janela, comunicacao e novo snapshot final quando autorizado."),
    ("OPS-06", "operacionais", "monitoramento_e_criterios_aborto_definidos pendente", "Metricas, alertas, limites de aborto e responsaveis pela reversao."),
)
INDEX = {x[0]: x for x in REQUIREMENTS}
CATEGORIES = ("lab", "bridge", "device-sensor02", "operacionais")
REFERENCE_RE = re.compile(r"^EV-A-[A-Z0-9]{6,32}$")
HASH_RE = re.compile(r"^[0-9a-f]{64}$")
KINDS = ("inventario-redigido", "observacao-operacional-redigida", "ensaio-isolado-redigido", "runbook-redigido", "deliberacao-independente-redigida")

def die(msg: str) -> None:
    raise ValueError(msg)

def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def sha_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(128 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def check_private_file(path: Path) -> None:
    if path.is_symlink():
        die("Symlink recusado para arquivo privado.")
    s = path.stat()
    if not stat.S_ISREG(s.st_mode) or (s.st_mode & 0o777) != 0o600 or s.st_nlink != 1 or s.st_uid != os.getuid():
        die("Arquivo privado deve ser regular, do usuario, 0600 e sem hardlinks.")

def check_dir(path: Path, create: bool) -> None:
    # Pais ja existentes devem nao ser links; restringimos o diretorio final a 0700.
    for par in (path, *path.parents):
        if par.is_symlink():
            die("Symlink no caminho do diretorio de estado.")
    if not path.exists():
        if not create:
            die("Diretorio de estado ausente: execute iniciar.")
        path.mkdir(parents=True, mode=0o700)
    s = path.stat()
    if not stat.S_ISDIR(s.st_mode) or (s.st_mode & 0o777) != 0o700 or s.st_uid != os.getuid():
        die("Diretorio privado deve pertencer ao usuario e ter modo 0700.")

def check_source(path: Path, *, directory: bool) -> None:
    if path.is_symlink() or not path.exists():
        die("Fonte C.7 ou snapshot ausente ou symlink; preflight bloqueado.")
    if directory and not path.is_dir():
        die("Snapshot nao e um diretorio.")
    if not directory:
        check_private_file(path)

def require_live_c7(snapshot: Path) -> None:
    """Reexecuta verificacao SOMENTE-LEITURA de C.7 contra origens atuais.

    Fail-closed: nao basta o hash do JSON C.7; a cadeia C.7 -> C.5 ->
    baseline -> C.3 precisa aprovar o snapshot atual. Nenhuma baixa de C-V1.
    """
    source = Path(__file__).with_name("fase8_4_5_4c7_coleta_evidencias.py")
    if source.is_symlink() or not source.is_file():
        die("C.7 ausente: bloqueada a verificacao das origens atuais.")
    # Importacao local do modulo de auditoria anterior; nao chama broker.
    spec = importlib.util.spec_from_file_location("_rust_c8_c7_gate", source)
    if spec is None or spec.loader is None:
        die("Nao foi possivel carregar auditoria C.7.")
    module = importlib.util.module_from_spec(spec)
    script_dir = str(source.parent)
    added = script_dir not in sys.path
    old_argv = sys.argv[:]
    try:
        if added:
            sys.path.insert(0, script_dir)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            spec.loader.exec_module(module)
            if not callable(getattr(module, "main", None)):
                die("C.7 sem funcao de verificacao.")
            arguments = ["verificar", "--snapshot", str(snapshot)]
            if len(inspect.signature(module.main).parameters) == 0:
                sys.argv = [str(source), *arguments]
                rc = module.main()
            else:
                rc = module.main(arguments)
        if rc not in (None, 0):
            die("C.7 reprovou o snapshot atual. Reavaliar 8.4.5.2 sem alterar o historico.")
    except (KeyboardInterrupt, SystemExit):
        die("C.7 nao concluiu a verificacao atual. Operacao C.8 bloqueada.")
    except Exception as error:
        # Nao imprimir payloads de excecao de modulos auxiliares.
        die("C.7 nao validou as origens atuais. Diagnosticar pela CLI C.7 original."
            f" (classe={type(error).__name__})")
    finally:
        sys.argv = old_argv
        if added:
            try:
                sys.path.remove(script_dir)
            except ValueError:
                pass

def initial(snapshot: Path, c7: Path) -> dict:
    check_source(snapshot, directory=True)
    check_source(c7, directory=False)
    return {
        "schema": SCHEMA,
        "scenario": "A",
        "baseline": {"snapshot": str(snapshot), "c7_path": str(c7), "c7_sha256": sha_file(c7)},
        "created_utc": now(),
        "requirements": [x[0] for x in REQUIREMENTS],
        "evidence": [],
        "approval": "NOT_GRANTED",
        "cutover_8883": "FORBIDDEN",
    }

def validate(obj: dict, *, check_baseline: bool = True) -> None:
    if not isinstance(obj, dict) or set(obj) != {"schema", "scenario", "baseline", "created_utc", "requirements", "evidence", "approval", "cutover_8883"}:
        die("Estrutura C.8 adulterada ou desconhecida.")
    if obj["schema"] != SCHEMA or obj["scenario"] != "A" or obj["approval"] != "NOT_GRANTED" or obj["cutover_8883"] != "FORBIDDEN":
        die("Gates de seguranca alterados.")
    if obj["requirements"] != [x[0] for x in REQUIREMENTS]:
        die("21 pendencias C-V1 alteradas.")
    b = obj["baseline"]
    if not isinstance(b, dict) or set(b) != {"snapshot", "c7_path", "c7_sha256"} or not isinstance(b["snapshot"], str) or not isinstance(b["c7_path"], str) or not isinstance(b["c7_sha256"], str) or not HASH_RE.fullmatch(b["c7_sha256"]):
        die("Baseline malformado.")
    if check_baseline:
        src = Path(b["c7_path"])
        check_source(Path(b["snapshot"]), directory=True)
        check_source(src, directory=False)
        if sha_file(src) != b["c7_sha256"]:
            die("C.7 modificado desde a inicializacao. Nao atualizar baseline automaticamente.")
    if not isinstance(obj["evidence"], list) or len(obj["evidence"]) > 210:
        die("Indice de evidencias invalido ou excessivo.")
    seen = set()
    digests = {}
    for item in obj["evidence"]:
        if not isinstance(item, dict) or set(item) != {"item_id", "reference", "sha256", "kind", "registered_utc", "review"}:
            die("Registro malformado.")
        ident, ref, digest = item["item_id"], item["reference"], item["sha256"]
        if ident not in INDEX or not isinstance(ref, str) or not REFERENCE_RE.fullmatch(ref) or not isinstance(digest, str) or not HASH_RE.fullmatch(digest) or item["kind"] not in KINDS or item["review"] != "pending-independent-review":
            die("Registro de evidencia fora da politica do cenario A.")
        if not isinstance(item["registered_utc"], str) or not item["registered_utc"].endswith("+00:00"):
            die("Timestamp invalido.")
        if (ident, ref) in seen:
            die("Referencia duplicada para o mesmo item.")
        seen.add((ident, ref))
        if ref in digests and digests[ref] != digest:
            die("Mesmo identificador opaco com dois hashes diferentes.")
        digests[ref] = digest

def load(path: Path) -> dict:
    check_dir(path.parent, create=False)
    check_private_file(path)
    with path.open(encoding="utf-8") as f:
        obj = json.load(f)
    validate(obj)
    return obj

def safe_write(path: Path, obj: dict, *, exclusive: bool) -> None:
    validate(obj)
    check_dir(path.parent, create=False)
    if exclusive and (path.exists() or path.is_symlink()):
        die("Indice C.8 ja existe. Preservar; nao sobrescrever.")
    if not exclusive:
        check_private_file(path)
    fd, temp = tempfile.mkstemp(prefix=".c8-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            os.fchmod(stream.fileno(), 0o600)
            json.dump(obj, stream, indent=2, ensure_ascii=False, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if exclusive:
            os.link(temp, path)  # atomico, falha se existir
            os.unlink(temp)
        else:
            os.replace(temp, path)
        dirfd = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)

def lock(path: Path):
    lockfile = path.with_name(path.name + ".lock")
    fd = os.open(lockfile, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    s = os.fstat(fd)
    if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o600 or s.st_nlink != 1 or not stat.S_ISREG(s.st_mode):
        os.close(fd)
        die("Lockfile inseguro.")
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd

def print_status(obj: dict) -> None:
    covered = {e["item_id"] for e in obj["evidence"]}
    for cat in CATEGORIES:
        ids = [i for i, group, *_ in REQUIREMENTS if group == cat]
        count = len(covered.intersection(ids))
        print(f"{cat}: {count}/{len(ids)} com metadados; {len(ids)} pendencias C-V1 SEM BAIXA")
    print(f"REFERENCIAS INDEXADAS: {len(obj['evidence'])} (nao exibidas)")
    print("REVISAO: todas pending-independent-review; nenhum registro comprova implantacao sozinho.")
    print("GATES: Seguranca, Git/CI, operacao, janela e snapshot final pendentes.")
    print("RESULTADO: C.8 documental; 21 pendencias originais; CORTE 8883 NAO AUTORIZADO.")

def make_parser():
    p = argparse.ArgumentParser(description="C.8: 21 pendencias C-V1; indice de evidencias do cenario A, sem corte")
    p.add_argument("--state", type=Path, default=STATE_DEFAULT, help="arquivo privado 0600 (padrao na pasta .config/rust-server)")
    sub = p.add_subparsers(dest="command", required=True)
    init = sub.add_parser("iniciar", help="criar indice privado uma vez, preservando C-V1/C.6/C.7")
    init.add_argument("--snapshot", type=Path, default=SNAPSHOT_DEFAULT)
    init.add_argument("--c7", type=Path, default=C7_DEFAULT)
    sub.add_parser("status", help="resumo sem referencias e sem segredos")
    sub.add_parser("roteiro", help="imprimir os 21 criterios e evidencias necessarias")
    sub.add_parser("verificar", help="validar formato, permissoes, baseline e bloqueios")
    reg = sub.add_parser("registrar", help="apontar evidencia A JA REDIGIDA e preservada fora do indice")
    reg.add_argument("--item", required=True, choices=sorted(INDEX))
    reg.add_argument("--referencia", required=True, help="id opaco EV-A-...; sem caminhos nem dados do cliente")
    reg.add_argument("--sha256", required=True, help="hash SHA-256 do documento externo JA REDIGIDO")
    reg.add_argument("--tipo", required=True, choices=KINDS)
    return p

def main(argv=None) -> int:
    a = make_parser().parse_args(argv)
    path = a.state.expanduser().absolute()
    try:
        if a.command == "roteiro":
            for i, group, desc, tip in REQUIREMENTS:
                print(f"{i} [{group}] PENDENTE: {desc}. Evidencia requerida: {tip}")
            print("SEPARAR A/B: lab 8884 e ensaios B nao comprovam cenario A.")
            print("21 pendencias sem baixa automatica; CORTE 8883 NAO AUTORIZADO.")
            return 0
        check_dir(path.parent, create=a.command == "iniciar")
        lockfd = lock(path) if a.command in ("iniciar", "registrar") else None
        try:
            if a.command == "iniciar":
                snapshot = a.snapshot.expanduser().absolute()
                obj = initial(snapshot, a.c7.expanduser().absolute())
                require_live_c7(snapshot)
                safe_write(path, obj, exclusive=True)
                print("APROVADO: indice C.8 privado criado (0600), sem alterar C-V1, C.6, C.7 ou brokers.")
                print_status(obj)
            else:
                obj = load(path)
                if a.command in ("verificar", "registrar"):
                    require_live_c7(Path(obj["baseline"]["snapshot"]))
                if a.command == "registrar":
                    ref, digest = a.referencia, a.sha256
                    if not REFERENCE_RE.fullmatch(ref) or not HASH_RE.fullmatch(digest):
                        die("Referencia opaca ou SHA-256 invalido; NUNCA usar segredo, Client ID, path ou texto livre.")
                    obj["evidence"].append({"item_id": a.item, "reference": ref, "sha256": digest, "kind": a.tipo, "registered_utc": now(), "review": "pending-independent-review"})
                    safe_write(path, obj, exclusive=False)
                    print(f"APROVADO: metadados de {a.item} registrados; revisao independente PENDENTE.")
                    print("Nenhuma pendencia C-V1 foi baixada.")
                elif a.command == "verificar":
                    print("APROVADO: estrutura, permissoes, integridade do baseline C.7 e gates de C.8 validados.")
                    print_status(obj)
                elif a.command == "status":
                    print_status(obj)
                    try:
                        require_live_c7(Path(obj["baseline"]["snapshot"]))
                    except ValueError:
                        print("BLOQUEADO: linha de base C.7 nao validada contra origem atual.")
                        return 2
                    print("APROVADO: verificacao C.7 atualizada para leitura do indice; nao concede prontidao.")
        finally:
            if lockfd is not None:
                os.close(lockfd)
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"BLOQUEADO: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
