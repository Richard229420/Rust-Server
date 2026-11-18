#!/usr/bin/env python3
"""Rust-Server 8.4.5.5-A: preparo documental e NO-GO para migracao MQTT.

Nao inicia, conecta, interrompe ou modifica brokers, credenciais, ACL, Git ou CI.
Apenas leitura do baseline C.7 e /proc/net/tcp*; a acao 'criar' grava
exclusivamente um plano novo e privado, sem possibilidade de sobrescrita.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

import fase8_4_5_2_preparar as p2
import fase8_4_5_4c_prontidao_corte as c
import fase8_4_5_4c3_evidencias as c3
import fase8_4_5_4c4_classificacao as c4
import fase8_4_5_4c5_avaliacao_operacional as c5
import fase8_4_5_4c6_inventario_operacional as c6
import fase8_4_5_4c7_coleta_evidencias as c7

PHASE = '8.4.5.5-A'
SCHEMA = 1
FILENAME = 'preparacao-corte-8455a.json'
MAX_BYTES = 32 * 1024
PORTS = (8883, 8884, 8895, 8896)
PENDING_EXPECTED = 21
ACTIONS = ('preflight', 'plano', 'criar', 'avaliar')
REQUIREMENTS = (
    'bridge_runtime_real_confirmado',
    'lab_escopo_operacional_e_politica_id_aprovados',
    'sensor02_implantacao_ou_exclusao_comprovada',
    'acl_produtiva_revisada_com_sensor01_revogado',
    'canal_autenticado_e_custodia_de_segredos_definidos',
    'rotacao_credenciais_documentada_e_homologada',
    'reconfiguracao_clientes_reais_homologada',
    'rollback_por_cliente_real_homologado',
    'rollback_broker_e_reconexao_planejados',
    'monitoramento_e_gatilhos_de_aborto_definidos',
    'janela_responsaveis_e_comunicacao_definidos',
    'snapshot_final_na_janela_previsto',
    'revisao_seguranca_formal',
    'revisao_git_ci_formal',
)
APPROVAL_KEYS = ('security', 'git_ci', 'operations')
SHA256 = re.compile(r'\A[a-f0-9]{64}\Z')


class Block(Exception):
    """Falha de seguranca sem detalhes privados na saida."""


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise Block(reason)


def listener_ports(proc_root: Path = Path('/proc/net')) -> dict[int, int] | None:
    """Consulta passiva de listeners TCP. Nunca faz connect/bind nem fecha processos.

    None = leitura indisponivel; nao interpretar como 'sem listeners'.
    """
    observed = {port: 0 for port in PORTS}
    for filename in ('tcp', 'tcp6'):
        try:
            path = proc_root / filename
            with path.open('r', encoding='ascii') as stream:
                header = next(stream, '')
                require('local_address' in header and 'st' in header,
                        'formato /proc/net/tcp desconhecido')
                for line in stream:
                    fields = line.split()
                    require(len(fields) >= 4, 'linha TCP inesperada')
                    if fields[3] != '0A':
                        continue  # estados que nao estao LISTEN
                    address = fields[1]
                    require(':' in address, 'endereco TCP inesperado')
                    try:
                        port = int(address.rsplit(':', 1)[1], 16)
                    except ValueError:
                        raise Block('porta TCP invalida') from None
                    if port in observed:
                        observed[port] += 1
        except (OSError, UnicodeError):
            return None
    return observed


def ports_report(observed: dict[int, int] | None) -> list[str]:
    if observed is None:
        return ['PORTAS: leitura passiva indisponivel; estado NAO CONFIRMADO.']
    require(set(observed) == set(PORTS) and all(type(n) is int and n >= 0
                                              for n in observed.values()),
            'dados de portas invalidos')
    return [f'PORTA {port}: '+ ('SEM LISTENER TCP' if observed[port] == 0
                                  else 'LISTENER TCP DETECTADO; revisar manualmente')
            for port in PORTS]


def verified_context(project: Path, snapshot: Path, private: Path,
                     backups: Path, plugin: Path) -> tuple[c5.Context, dict, str]:
    """Exige C-v1, C-v2, C.6 e C.7, sem aceitar ensaios B como producao A."""
    require(os.geteuid() != 0, 'nao executar como root')
    context, index = c7.verified_context(project, snapshot, private, backups, plugin)
    require(len(context.pending) == PENDING_EXPECTED,
            'quantidade de pendencias alterada; revisao manual')
    collection = c7.read_collection(private, context.fingerprint)
    c7.validate(collection, context.fingerprint)
    require(collection['c_v1_pending'] == PENDING_EXPECTED and
            collection['cutover_authorized'] is False and
            all(x is False for x in collection['external_approvals'].values()),
            'coleta C.7 nao e um baseline de bloqueio')
    # A coleta C.7 e historica. O hash vincula o plano a ela, nao comprova
    # clientes reais nem atesta estado atual dos processos ou das portas.
    raw = p2.check_regular(c7.collection_path(private), private=True, limit=c7.MAX_BYTES)
    checksum = hashlib.sha256(raw).hexdigest()
    require(SHA256.fullmatch(checksum) is not None, 'hash invalido')
    c6.validate(index, context.fingerprint)
    return context, collection, checksum


def template(snapshot_fp: str, c7_digest: str) -> dict:
    require(type(snapshot_fp) is str and SHA256.fullmatch(snapshot_fp) is not None and
            type(c7_digest) is str and SHA256.fullmatch(c7_digest) is not None,
            'vinculo de evidencias invalido')
    return {
        'schema': SCHEMA,
        'phase': PHASE,
        'snapshot_manifest_sha256': snapshot_fp,
        'c7_collection_sha256': c7_digest,
        'scenario_primary': 'A',
        'scenario_secondary': 'B',
        'mode': 'preparation-only',
        'cutover_authorized': False,
        'decision': 'NO-GO',
        'approvals': {key: False for key in APPROVAL_KEYS},
        'c_v1_pending': PENDING_EXPECTED,
        'requirements': {key: 'pending-independent-evidence' for key in REQUIREMENTS},
        'client_scope': {name: 'unverified' for name in c.ACCOUNTS},
        'revoked_excluded': True,
        'final_snapshot_captured': False,
        'rollback_8883_executed': False,
    }


def validate(record: object, snapshot_fp: str, c7_digest: str) -> None:
    require(isinstance(record, dict), 'plano invalido')
    expected = template(snapshot_fp, c7_digest)
    require(set(record) == set(expected), 'plano com campos inesperados')
    for key in expected:
        if key in ('approvals', 'requirements', 'client_scope'):
            require(type(record[key]) is dict and set(record[key]) == set(expected[key]) and
                    all(type(v) is type(expected[key][k]) and v == expected[key][k]
                        for k, v in record[key].items()),
                    'plano alterado ou aprovacao indevida')
        elif key in ('schema', 'c_v1_pending'):
            require(type(record[key]) is int and record[key] == expected[key],
                    'numero alterado no plano')
        elif key in ('cutover_authorized', 'revoked_excluded',
                     'final_snapshot_captured', 'rollback_8883_executed'):
            require(type(record[key]) is bool and record[key] is expected[key],
                    'autorizacao ou estado operacional indevido')
        else:
            require(type(record[key]) is str and record[key] == expected[key],
                    'vinculo ou decisao do plano alterado')


def plan_path(private: Path) -> Path:
    try:
        return c.private_folder(private, create=False) / FILENAME
    except c.Block:
        raise Block('diretorio privado inseguro') from None


def create_plan(private: Path, snapshot_fp: str, c7_digest: str) -> None:
    record = template(snapshot_fp, c7_digest)
    validate(record, snapshot_fp, c7_digest)
    dest = plan_path(private)
    require(not dest.exists() and not dest.is_symlink(),
            'plano existente; nao sobrescrever')
    raw = (json.dumps(record, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
    require(len(raw) <= MAX_BYTES, 'plano excessivo')
    try:
        p2.write_exclusive(dest, raw)
        p2.check_regular(dest, private=True, limit=MAX_BYTES)
    except (OSError, p2.Block):
        raise Block('falha de gravacao privada') from None


def read_plan(private: Path, snapshot_fp: str, c7_digest: str) -> dict:
    try:
        raw = p2.check_regular(plan_path(private), private=True, limit=MAX_BYTES)
        doc = json.loads(raw)
    except (OSError, ValueError, TypeError, UnicodeError, p2.Block):
        raise Block('plano privado ausente ou inseguro') from None
    validate(doc, snapshot_fp, c7_digest)
    return doc


def safe_plan() -> str:
    return '\n'.join([
        '=== FASE 8.4.5.5-A — PREPARACAO DOCUMENTAL, NUNCA CORTE ===',
        'CENARIO A: operacao principal; B: laboratorio/homologacao isolado.',
        '01 INVENTARIO: evidencias reais de bridge, lab e sensor02, ou exclusao formal.',
        '02 ACL: revisao por Seguranca; sensor01 revogado permanece excluido.',
        '03 SEGREDOS: canal autenticado, custodia, plano de rotacao e retorno.',
        '04 HOMOLOGACAO: reconfiguracao e rollback por cliente real, fora de producao.',
        '05 ROLLBACK: restaure somente sob autorizacao futura; validar reconexao de todos os clientes.',
        '06 OPERACAO: janela, responsaveis, comunicacao, monitoramento e gatilhos de aborto.',
        '07 BACKUP: snapshot 8.4.5.2 preservado; snapshot FINAL apenas na janela aprovada.',
        '08 REVISOES: decisoes formais de Seguranca e Git/CI; CI verde isolado nao autoriza corte.',
        '09 DECISAO FUTURA: conferencia GO/NO-GO independente, antes de qualquer mudanca 8883.',
        'NAO EXECUTAR AGORA: mosquitto, mosquitto_ctrl, systemctl, alteracao ACL/PKI, rotacao,',
        '  git add/commit/push, rollback real, restart ou corte de 8883/8884.',
        'RESULTADO: plano PREPARATORIO, NO-GO; 8883 NAO AUTORIZADO.',
    ])


def safe_status(ctx: c5.Context, observed: dict[int, int] | None) -> str:
    group = c5.counts(ctx.pending)
    return '\n'.join([
        '=== FASE 8.4.5.5-A — PRONTIDAO PARA PLANEJAMENTO (NO-GO) ===',
        'BASELINE: C-v1/C-v2/C.6/C.7 verificados localmente; sem prova de cliente operacional.',
        'CENARIO A: principal; B: laboratorio, sem transferencia automatica de evidencia.',
        'PENDENCIAS C-V1: ' + str(len(ctx.pending)) + ' (' +
        ', '.join(f'{key}={group[key]}' for key in (*c.ACCOUNTS,'operacionais')) + ').',
        *ports_report(observed),
        'REQUISITOS 8.4.5.5-A: ' + str(len(REQUIREMENTS)) + ' aguardam comprovacao/revisao independente.',
        'GATES: Seguranca, Git/CI e Operacao NAO aprovados por esta ferramenta.',
        'SNAPSHOT: 8.4.5.2 validado; backup final ainda nao capturado nesta etapa.',
        'REVOGACAO: device-sensor01 nao deve ser reabilitado.',
        'DECISAO: NO-GO; CORTE 8883 NAO AUTORIZADO.',
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home()/'.config/rust-server')
    parser.add_argument('--backups-root', type=Path,
                        default=Path.home()/'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    args = parser.parse_args(argv)
    try:
        project, snapshot, private, backups, plugin = (
            p.absolute() for p in (args.project_root, args.snapshot,
                                    args.private_root, args.backups_root, args.plugin_path))
        ctx, _collection, c7_hash = verified_context(project, snapshot, private,
                                                      backups, plugin)
        if args.action == 'preflight':
            print('APROVADO: verificacoes documentais C-v1/C-v2/C.6/C.7 e snapshot conferidas.')
            print(safe_status(ctx, listener_ports()))
        elif args.action == 'plano':
            print(safe_plan())
        elif args.action == 'criar':
            create_plan(private, ctx.fingerprint, c7_hash)
            print('APROVADO: plano 8.4.5.5-A criado em local privado 0600; cadastros preservados.')
            print('DECISAO: NO-GO; CORTE 8883 NAO AUTORIZADO.')
        else:
            read_plan(private, ctx.fingerprint, c7_hash)
            print('APROVADO: estrutura, vinculos e permissoes do plano privado 8.4.5.5-A verificados.')
            print(safe_status(ctx, listener_ports()))
            return 3  # pendencias operacionais: nao significa erro no script
        return 0
    except (Block, c7.Block, c6.Block, c5.Block, c4.Block, c3.Block,
            c.Block, p2.Block, OSError, TypeError, ValueError, UnicodeError):
        print('BLOQUEIO: baseline ou plano privado inconsistente; sem alteracao de brokers. '
              'CORTE 8883 NAO AUTORIZADO.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
