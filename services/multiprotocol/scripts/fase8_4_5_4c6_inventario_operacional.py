#!/usr/bin/env python3
"""Fase 8.4.5.4-C.6: inventario passivo e indice privado de evidencias do cenario A.

Nao conecta a rede, nao inicia MQTT, nao le valores de variaveis, nao altera os
cadastros C-v1/C-v2, nao comprova automaticamente cliente real nem autoriza corte.
'registrar' indexa apenas referencias e hashes de evidencias JA REDIGIDAS,
sempre como NAO REVISADAS; nao importa arquivos de origem.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys

import fase8_4_5_2_preparar as p2
import fase8_4_5_4c_prontidao_corte as c
import fase8_4_5_4c3_evidencias as c3
import fase8_4_5_4c4_classificacao as c4
import fase8_4_5_4c5_avaliacao_operacional as c5

PHASE = '8.4.5.4-C.6'
SCHEMA = 3
FILENAME = 'evidencias-operacionais-c6.json'
ACTIONS = ('preflight', 'inventariar', 'plano', 'criar', 'registrar', 'avaliar')
EVIDENCE_KINDS = (
    'runtime-redacted', 'configuration-redacted', 'client-change-lab',
    'rollback-lab', 'not-deployed-inventory', 'operator-scope',
)
SHA256 = re.compile(r'\A[a-f0-9]{64}\Z')
MAX_FILE = 32 * 1024
MAX_PER_IDENTITY = 8
# Inspecionar somente nomes de variaveis ja conhecidas: NUNCA seus valores.
SAFE_ENV_NAMES = frozenset({
    'RUST_SERVER_MQTT_BRIDGE_PASSWORD', 'RUST_SERVER_MQTT_LAB_PASSWORD',
    'RUST_SERVER_TLS_CA', 'RUST_SERVER_MQTT_ADDR',
})
# Apenas pistas de processos locais, NAO identificacao confiavel de clientes.
SAFE_COMM = frozenset({'multiprotocol', 'mosquitto', 'mosquitto_sub', 'mosquitto_pub'})


class Block(Exception):
    """Erro de seguranca que nao deve revelar detalhes do arquivo privado."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Block(message)


def template(fingerprint: str) -> dict:
    require(SHA256.fullmatch(fingerprint) is not None, 'impressao de snapshot invalida')
    return {
        'schema': SCHEMA,
        'phase': PHASE,
        'snapshot_manifest_sha256': fingerprint,
        'scenario': 'A',
        'cutover_authorized': False,
        'approvals': {'security': False, 'git_ci': False, 'operational': False},
        'identities': {identity: [] for identity in c.ACCOUNTS},
    }


def validate(model: dict, fingerprint: str) -> None:
    require(isinstance(model, dict) and set(model) == {
        'schema', 'phase', 'snapshot_manifest_sha256', 'scenario',
        'cutover_authorized', 'approvals', 'identities'},
        'estrutura inesperada do indice C.6')
    require(type(model['schema']) is int and model['schema'] == SCHEMA and
            model['phase'] == PHASE and model['scenario'] == 'A' and
            model['snapshot_manifest_sha256'] == fingerprint and
            model['cutover_authorized'] is False,
            'indice ou vinculo do snapshot invalido; corte nao autorizado')
    require(isinstance(model['approvals'], dict) and
            model['approvals'] == {'security': False, 'git_ci': False, 'operational': False},
            'aprovacoes nao podem ser concedidas aqui')
    identities = model['identities']
    require(isinstance(identities, dict) and set(identities) == set(c.ACCOUNTS),
            'identidades invalidas ou revogadas')
    encountered = set()
    for identity in c.ACCOUNTS:
        records = identities[identity]
        require(isinstance(records, list) and len(records) <= MAX_PER_IDENTITY,
                'numero excessivo de referencias')
        for entry in records:
            require(isinstance(entry, dict) and set(entry) ==
                    {'kind', 'reference', 'redacted_sha256', 'review_status'},
                    'registro de evidencia invalido')
            kind, reference, digest = (entry['kind'], entry['reference'],
                                       entry['redacted_sha256'])
            require(type(kind) is str and kind in EVIDENCE_KINDS and
                    c4.safe_reference(reference) and type(digest) is str and
                    SHA256.fullmatch(digest) is not None and
                    entry['review_status'] == 'pending-independent-review',
                    'evidencia malformada ou indevidamente aprovada')
            unique = (reference, digest)
            require(unique not in encountered, 'referencia duplicada entre identidades')
            encountered.add(unique)


def index_path(private_root: Path) -> Path:
    return c.private_folder(private_root, create=False) / FILENAME


def read_index(private_root: Path, fingerprint: str) -> dict:
    try:
        raw = p2.check_regular(index_path(private_root), private=True, limit=MAX_FILE)
        model = json.loads(raw)
    except (OSError, ValueError, UnicodeError, p2.Block):
        raise Block('indice privado C.6 ausente ou inseguro') from None
    validate(model, fingerprint)
    return model


def create_index(private_root: Path, fingerprint: str) -> None:
    destination = index_path(private_root)
    require(not destination.exists() and not destination.is_symlink(),
            'indice ja existe; nao sobrescrever')
    doc = template(fingerprint)
    payload = (json.dumps(doc, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    try:
        p2.write_exclusive(destination, payload)
        p2.check_regular(destination, private=True, limit=MAX_FILE)
    except (OSError, p2.Block):
        raise Block('falha ao criar indice privado') from None


def add_reference(model: dict, fingerprint: str, *, identity: str, kind: str,
                  reference: str, digest: str) -> dict:
    validate(model, fingerprint)
    require(identity in c.ACCOUNTS and kind in EVIDENCE_KINDS and
            c4.safe_reference(reference) and isinstance(digest, str) and
            SHA256.fullmatch(digest) is not None,
            'identidade, tipo ou referencia invalida')
    updated = copy.deepcopy(model)
    entry = {'kind': kind, 'reference': reference, 'redacted_sha256': digest,
             'review_status': 'pending-independent-review'}
    bucket = updated['identities'][identity]
    if entry in bucket:
        return updated
    require(all(item['reference'] != reference for item in bucket),
            'referencia divergente; revisao manual necessaria')
    bucket.append(entry)
    validate(updated, fingerprint)
    return updated


def save_index(private_root: Path, old: dict, new: dict, fingerprint: str) -> bool:
    validate(old, fingerprint)
    validate(new, fingerprint)
    source = index_path(private_root)
    raw, meta = c3.secured_original(source)
    try:
        same = json.loads(raw) == old
    except (ValueError, UnicodeError):
        same = False
    require(same, 'indice alterado desde a leitura')
    try:
        return c3.atomic_save_model(source, raw, meta, new)
    except c3.Block:
        raise Block('falha ao atualizar indice privado') from None


def declared_keys(env_file: Path) -> frozenset[str] | None:
    """Extrai apenas CHAVES predefinidas, sem exibir ou armazenar valores."""
    if not env_file.exists() and not env_file.is_symlink():
        return None
    try:
        raw = p2.check_regular(env_file, private=False, limit=128 * 1024)
    except p2.Block:
        raise Block('arquivo env inseguro; nao foi examinado') from None
    names = set()
    pattern = re.compile(rb'^\s*(?:export\s+)?(RUST_SERVER_[A-Za-z0-9_]+)\s*=')
    for line in raw.splitlines():
        match = pattern.match(line)
        if match:
            name = match.group(1).decode('ascii')
            if name in SAFE_ENV_NAMES:
                names.add(name)
    return frozenset(names)


def passive_process_counts(proc_root: Path = Path('/proc')) -> dict[str, int] | None:
    """Le /proc/PID/comm; nao le cmdline, environ ou parametros do processo."""
    try:
        dirs = tuple(proc_root.iterdir())
    except OSError:
        return None
    result = {name: 0 for name in SAFE_COMM}
    for item in dirs:
        if not item.name.isdecimal() or item.is_symlink():
            continue
        path = item / 'comm'
        if path.is_symlink():
            continue
        try:
            with path.open('rb') as reader:
                raw = reader.read(64)
        except (OSError, PermissionError):
            continue
        try:
            name = raw.strip().decode('ascii')
        except UnicodeError:
            continue
        if name in SAFE_COMM:
            result[name] += 1
    return result


def static_inventory(project: Path, proc_root: Path = Path('/proc')) -> dict:
    """Contexto local, nunca comprovacao de cliente implantado ou remoto."""
    # c3.verify_bridge_source, chamado no preflight, valida a fonte com pins.
    declared = declared_keys(project / 'scripts/env_phase8.sh')
    processes = passive_process_counts(proc_root)
    return {'env': declared, 'processes': processes}


def report_inventory(inventory: dict, pending: tuple[str, ...]) -> str:
    env = inventory['env']
    processes = inventory['processes']
    lines = [
        '=== 8.4.5.4-C.6 — INVENTARIO PASSIVO DO HOST ===',
        'BRIDGE: ID estatico na fonte Rust conferido no preflight; runtime NAO confirmado.',
        'ENV: ' + ('arquivo nao encontrado' if env is None else
                   'apenas declaracoes de nomes examinadas, nunca os valores'),
    ]
    for name in sorted(SAFE_ENV_NAMES):
        lines.append('  ' + name + ': ' +
                     ('indisponivel' if env is None else ('declarada' if name in env else 'nao declarada')))
    if processes is None:
        lines.append('PROCESSOS: consulta local indisponivel.')
    else:
        for name in sorted(SAFE_COMM):
            lines.append('PROCESSOS possiveis ' + name + ': ' + str(processes[name]))
    lines.extend([
        'LAB: scripts e credenciais configuraveis nao comprovam operador ativo.',
        'SENSOR02: nao inferir dispositivo/firmware remoto a partir do host local.',
        'REVOGADO: device-sensor01 mantido fora do escopo.',
        'PENDENCIAS C-V1: ' + str(len(pending)) + '.',
        'LIMITE: nomes de processos e variaveis NAO comprovam configuracao operacional.',
        'RESULTADO: inventario passivo; CORTE 8883 NAO AUTORIZADO.',
    ])
    return '\n'.join(lines)


def report_evidence(model: dict, fingerprint: str, pending: tuple[str, ...]) -> str:
    validate(model, fingerprint)
    lines = ['=== 8.4.5.4-C.6 — INDICE PRIVADO DE EVIDENCIAS (SEM APROVACAO) ===']
    for identity in c.ACCOUNTS:
        records = model['identities'][identity]
        lines.append(identity + ': ' + str(len(records)) +
                     ' referencias declaradas; ' + str(len(records)) + ' aguardando revisao independente.')
    lines.extend([
        'C-V1: ' + str(len(pending)) + ' pendencias; nao alteradas pela C.6.',
        'REFERENCIAS: nao exibidas; hashes e relatos NAO provam autenticidade ou implantacao.',
        'CENARIO B: evidencia de ensaio nao comprova cliente do CENARIO A.',
        'GATES: Seguranca, Git/CI e operacao ainda externos.',
        'RESULTADO: CORTE 8883 NAO AUTORIZADO.',
    ])
    return '\n'.join(lines)


def plan() -> str:
    return '\n'.join([
        '=== 8.4.5.4-C.6 — REQUISITOS DE COMPROVACAO DO CENARIO A ===',
        'BRIDGE: coletar comprovante REDIGIDO do processo/servico real, ID efetivo, TLS,',
        '  destino 127.0.0.1:8883 e procedimento de troca/retorno em homologacao.',
        'LAB: catalogar operadores/instancias reais; politica de IDs e ACL minima',
        '  dependem de revisao de Seguranca. IDs CLI dinamicos de B nao comprovam A.',
        'SENSOR02: comprovar dispositivo ou servico, ID e configuracao efetivos;',
        '  se nao implantado, registrar evidencias de inventario e decidir exclusao formal.',
        'EVIDENCIAS: redigir conteudo FORA deste script; excluir senhas, tokens, chaves',
        '  privadas, dados pessoais, MAC/IP sensivel, cabecalhos de autorizacao.',
        '  Indexar APENAS referencia opaca e SHA256 de evidencia ja redigida.',
        'ROLLBACK: testar troca e retorno POR CLIENTE REAL em ambiente isolado;',
        '  nao reutilizar credenciais de ensaio como credenciais de producao.',
        'OPERACAO: definir canal, janela, responsaveis, aborto, monitoração e backup final.',
        'GATES: Seguranca, Git/CI e prontidao independentes; 21 pendencias C-v1',
        '  nao sao baixadas automaticamente pela C.6.',
        'NAO EXECUTAR: Mosquitto, migracao 8883, ACL, rotacao real, Git push ou rollback real.',
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('--snapshot', required=True, type=Path)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--backups-root', type=Path, default=Path.home() / 'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    parser.add_argument('--identidade', choices=c.ACCOUNTS)
    parser.add_argument('--tipo', choices=EVIDENCE_KINDS)
    parser.add_argument('--referencia')
    parser.add_argument('--sha256')
    args = parser.parse_args(argv)
    try:
        params = (args.identidade, args.tipo, args.referencia, args.sha256)
        require((args.action == 'registrar' and all(params)) or
                (args.action != 'registrar' and not any(params)),
                'argumentos de registro incompletos ou indevidos')
        project, snapshot, private, backups, plugin = (
            p.absolute() for p in (args.project_root, args.snapshot, args.private_root,
                                    args.backups_root, args.plugin_path))
        ctx = c5.verified_context(project, snapshot, private, backups, plugin)
        if args.action == 'preflight':
            print('APROVADO: baseline, C-v1 e C-v2, branch e fontes revisadas conferidos.')
            print('C-V1: ' + str(len(ctx.pending)) + ' pendencias; CORTE 8883 NAO AUTORIZADO.')
        elif args.action == 'inventariar':
            print(report_inventory(static_inventory(project), ctx.pending))
        elif args.action == 'plano':
            print(plan())
        elif args.action == 'criar':
            create_index(private, ctx.fingerprint)
            print('APROVADO: indice C.6 PRIVADO criado; C-v1 e C-v2 preservados.')
            print(report_evidence(read_index(private, ctx.fingerprint), ctx.fingerprint, ctx.pending))
        elif args.action == 'registrar':
            old = read_index(private, ctx.fingerprint)
            new = add_reference(old, ctx.fingerprint, identity=args.identidade,
                                kind=args.tipo, reference=args.referencia,
                                digest=args.sha256)
            written = save_index(private, old, new, ctx.fingerprint)
            print('REFERENCIA INDEXADA; aguarda revisao independente.' if written else
                  'REFERENCIA JA INDEXADA; sem alteracoes.')
            print(report_evidence(read_index(private, ctx.fingerprint), ctx.fingerprint, ctx.pending))
        else:
            print(report_evidence(read_index(private, ctx.fingerprint), ctx.fingerprint, ctx.pending))
        return 0
    except (Block, c5.Block, c4.Block, c3.Block, c.Block, p2.Block,
            ValueError, OSError, TypeError, UnicodeError):
        print('BLOQUEIO: indice, evidencias ou baseline invalido; nenhuma operacao MQTT realizada; '
              'CORTE 8883 NAO AUTORIZADO.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
