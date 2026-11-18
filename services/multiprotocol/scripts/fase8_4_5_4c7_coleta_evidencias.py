#!/usr/bin/env python3
"""Fase 8.4.5.4-C.7: coleta LOCAL, PASSIVA e privada de evidencias.

Cenario A e primario; B e laboratorio. Nao abre sockets, nao executa clientes,
nao persiste nem exibe valores de variaveis, nao altera C-v1/C-v2/C.6, nem fecha pendencias.
A coleta e um registro de pistas locais, NAO comprovacao de implantacao.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import stat
import sys

import fase8_4_5_2_preparar as p2
import fase8_4_5_4c_prontidao_corte as c
import fase8_4_5_4c3_evidencias as c3
import fase8_4_5_4c4_classificacao as c4
import fase8_4_5_4c5_avaliacao_operacional as c5
import fase8_4_5_4c6_inventario_operacional as c6

PHASE = '8.4.5.4-C.7'
SCHEMA = 4
FILENAME = 'coleta-passiva-c7.json'
MAX_BYTES = 32 * 1024
ACTIONS = ('preflight', 'coletar', 'verificar', 'resumo', 'roteiro')
PENDING_REQUIRED = 21
BRIDGE_ID_FROM_PINNED_SOURCE = 'rust-server-bridge-local'
SCRIPT_NAMES = (
    'test_phase8_1_mqtt_auth.sh',
    'diagnosticar_mqtt_fase8.sh',
    'test_phase8_3_devices.sh',
)
TIMESTAMP = re.compile(r'\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00\Z')
APPROVALS = {'security': False, 'git_ci': False, 'operational': False}


class Block(Exception):
    """Negativa sem expor informacoes privadas em stdout ou stderr."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Block(message)


def ordinary_file_exists(path: Path) -> bool:
    """Testa somente nome/metadados, sem abrir nem seguir um symlink."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise Block('arquivo local nao verificavel') from None
    require(not stat.S_ISLNK(metadata.st_mode), 'link simbolico inesperado em script')
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1,
            'script nao e arquivo regular exclusivo')
    return True


def _declared(names: frozenset[str] | None, name: str) -> bool | None:
    return None if names is None else name in names


def _process_count(counts: dict[str, int] | None, name: str) -> int | None:
    return None if counts is None else counts[name]


def collect(project: Path, context: c5.Context, index: dict,
            proc_root: Path = Path('/proc'),
            observed_at: str | None = None) -> dict:
    """Constroi somente fatos estaticos/pistas no host; sem comprovacao operacional."""
    require(len(context.pending) == PENDING_REQUIRED,
            'quantidade de pendencias alterada; revisao manual necessaria')
    c4.validate(context.classification, context.fingerprint)
    c6.validate(index, context.fingerprint)
    env_and_processes = c6.static_inventory(project, proc_root)
    declared = env_and_processes['env']
    processes = env_and_processes['processes']
    scripts = {name: ordinary_file_exists(project / 'scripts' / name)
               for name in SCRIPT_NAMES}
    now = observed_at if observed_at is not None else datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    payload = {
        'schema': SCHEMA,
        'phase': PHASE,
        'snapshot_manifest_sha256': context.fingerprint,
        'collected_at_utc': now,
        'collection_mode': 'passive-local-metadata-only',
        'scenario_primary': 'A',
        'scenario_secondary': 'B',
        'cutover_authorized': False,
        'external_approvals': dict(APPROVALS),
        'c_v1_pending': PENDING_REQUIRED,
        'clients': {
            'bridge': {
                'source_pinned_by_c3': True,
                'source_client_id': BRIDGE_ID_FROM_PINNED_SOURCE,
                'bridge_password_env_name_declared': _declared(declared, 'RUST_SERVER_MQTT_BRIDGE_PASSWORD'),
                'tls_ca_env_name_declared': _declared(declared, 'RUST_SERVER_TLS_CA'),
                'mqtt_addr_env_name_declared': _declared(declared, 'RUST_SERVER_MQTT_ADDR'),
                'possible_processes': _process_count(processes, 'multiprotocol'),
                'operational_runtime_proven': False,
            },
            'lab': {
                'lab_password_env_name_declared': _declared(declared, 'RUST_SERVER_MQTT_LAB_PASSWORD'),
                'cli_script_files_present': {k: scripts[k] for k in SCRIPT_NAMES[:2]},
                'possible_pub_processes': _process_count(processes, 'mosquitto_pub'),
                'possible_sub_processes': _process_count(processes, 'mosquitto_sub'),
                'operators_or_deployment_proven': False,
                'scenario_a_policy_approved': False,
            },
            'device-sensor02': {
                'device_test_script_file_present': scripts['test_phase8_3_devices.sh'],
                'remote_device_examined': False,
                'actual_deployment_proven': False,
            },
        },
        'classification_declarations': {
            scenario: {
                identity: context.classification['scenarios'][scenario]['identities'][identity]['deployment']
                for identity in c.ACCOUNTS
            }
            for scenario in c4.SCENARIOS
        },
        'c6_indexed_reference_counts': {
            identity: len(index['identities'][identity]) for identity in c.ACCOUNTS
        },
        'limitations': {
            'cli_and_firmware_not_inspected': True,
            'process_counts_not_runtime_attestations': True,
            'lab_evidence_does_not_prove_scenario_a': True,
            'no_client_credential_change_tested': True,
            'no_client_rollback_tested': True,
            'no_broker_contact': True,
            'no_c_v1_c_v2_c6_writes': True,
        },
    }
    validate(payload, context.fingerprint)
    return payload


def _optional_bool(value: object) -> bool:
    return value is None or type(value) is bool


def _optional_count(value: object) -> bool:
    return value is None or (type(value) is int and 0 <= value <= 100000)


def validate(model: object, fingerprint: str) -> None:
    require(isinstance(model, dict) and set(model) == {
        'schema', 'phase', 'snapshot_manifest_sha256', 'collected_at_utc',
        'collection_mode', 'scenario_primary', 'scenario_secondary',
        'cutover_authorized', 'external_approvals', 'c_v1_pending', 'clients',
        'classification_declarations', 'c6_indexed_reference_counts', 'limitations'},
        'estrutura de coleta invalida')
    require(type(model['schema']) is int and model['schema'] == SCHEMA and
            model['phase'] == PHASE and model['snapshot_manifest_sha256'] == fingerprint and
            model['collection_mode'] == 'passive-local-metadata-only' and
            model['scenario_primary'] == 'A' and model['scenario_secondary'] == 'B' and
            model['cutover_authorized'] is False and
            isinstance(model['external_approvals'], dict) and
            set(model['external_approvals']) == set(APPROVALS) and
            all(val is False for val in model['external_approvals'].values()) and
            type(model['c_v1_pending']) is int and model['c_v1_pending'] == PENDING_REQUIRED,
            'coleta nao vinculada ao baseline ou controles de corte violados')
    require(type(model['collected_at_utc']) is str and
            TIMESTAMP.fullmatch(model['collected_at_utc']) is not None,
            'instante de coleta invalido')
    clients = model['clients']
    require(isinstance(clients, dict) and set(clients) == set(c.ACCOUNTS),
            'cliente inesperado ou revogado')
    bridge, lab, sensor = (clients['bridge'], clients['lab'], clients['device-sensor02'])
    require(isinstance(bridge, dict) and set(bridge) == {
        'source_pinned_by_c3', 'source_client_id', 'bridge_password_env_name_declared',
        'tls_ca_env_name_declared', 'mqtt_addr_env_name_declared',
        'possible_processes', 'operational_runtime_proven'}, 'bridge invalida')
    require(bridge['source_pinned_by_c3'] is True and
            bridge['source_client_id'] == BRIDGE_ID_FROM_PINNED_SOURCE and
            bridge['operational_runtime_proven'] is False and
            all(_optional_bool(bridge[k]) for k in (
                'bridge_password_env_name_declared', 'tls_ca_env_name_declared',
                'mqtt_addr_env_name_declared')) and
            _optional_count(bridge['possible_processes']), 'evidencia bridge nao comprovada')
    require(isinstance(lab, dict) and set(lab) == {
        'lab_password_env_name_declared', 'cli_script_files_present',
        'possible_pub_processes', 'possible_sub_processes',
        'operators_or_deployment_proven', 'scenario_a_policy_approved'}, 'lab invalido')
    require(_optional_bool(lab['lab_password_env_name_declared']) and
            lab['operators_or_deployment_proven'] is False and
            lab['scenario_a_policy_approved'] is False and
            isinstance(lab['cli_script_files_present'], dict) and
            set(lab['cli_script_files_present']) == set(SCRIPT_NAMES[:2]) and
            all(type(v) is bool for v in lab['cli_script_files_present'].values()) and
            _optional_count(lab['possible_pub_processes']) and
            _optional_count(lab['possible_sub_processes']), 'evidencia lab nao comprovada')
    require(isinstance(sensor, dict) and set(sensor) == {
        'device_test_script_file_present', 'remote_device_examined',
        'actual_deployment_proven'}, 'sensor invalido')
    require(type(sensor['device_test_script_file_present']) is bool and
            sensor['remote_device_examined'] is False and
            sensor['actual_deployment_proven'] is False, 'sensor real nao comprovado')
    declarations = model['classification_declarations']
    require(isinstance(declarations, dict) and set(declarations) == {'A', 'B'},
            'matriz de cenarios inesperada')
    for scenario in ('A', 'B'):
        vals = declarations[scenario]
        require(isinstance(vals, dict) and set(vals) == set(c.ACCOUNTS) and
                all(type(val) is str and val in c4.DEPLOYMENTS for val in vals.values()),
                'status de implantacao invalido')
    counts = model['c6_indexed_reference_counts']
    require(isinstance(counts, dict) and set(counts) == set(c.ACCOUNTS) and
            all(type(val) is int and 0 <= val <= c6.MAX_PER_IDENTITY for val in counts.values()),
            'contagem do indice C.6 invalida')
    required_limits = {
        'cli_and_firmware_not_inspected', 'process_counts_not_runtime_attestations',
        'lab_evidence_does_not_prove_scenario_a', 'no_client_credential_change_tested',
        'no_client_rollback_tested', 'no_broker_contact', 'no_c_v1_c_v2_c6_writes',
    }
    require(isinstance(model['limitations'], dict) and
            set(model['limitations']) == required_limits and
            all(value is True for value in model['limitations'].values()),
            'limites de coleta foram alterados')


def collection_path(private_root: Path) -> Path:
    return c.private_folder(private_root, create=False) / FILENAME


def write_once(private_root: Path, data: dict, fingerprint: str) -> Path:
    validate(data, fingerprint)
    target = collection_path(private_root)
    require(not target.exists() and not target.is_symlink(),
            'coleta C.7 ja existente; preservar e verificar')
    payload = (json.dumps(data, ensure_ascii=False, sort_keys=True, indent=2) + '\n').encode('utf-8')
    require(len(payload) <= MAX_BYTES, 'coleta grande demais')
    try:
        p2.write_exclusive(target, payload)
        p2.check_regular(target, private=True, limit=MAX_BYTES)
    except (OSError, p2.Block):
        raise Block('falha em gravar coleta privada C.7') from None
    return target


def read_collection(private_root: Path, fingerprint: str) -> dict:
    try:
        raw = p2.check_regular(collection_path(private_root), private=True, limit=MAX_BYTES)
        payload = json.loads(raw)
    except (OSError, ValueError, UnicodeError, p2.Block):
        raise Block('coleta C.7 ausente ou arquivo inseguro') from None
    validate(payload, fingerprint)
    return payload


def safe_summary(model: dict, fingerprint: str) -> str:
    validate(model, fingerprint)
    bridge = model['clients']['bridge']
    lab = model['clients']['lab']
    sensor = model['clients']['device-sensor02']
    count_bridge = bridge['possible_processes']
    count_pub, count_sub = lab['possible_pub_processes'], lab['possible_sub_processes']
    readable = lambda n: 'indisponivel' if n is None else str(n)
    lines = [
        '=== RUST-SERVER 8.4.5.4-C.7 — COLETA PASSIVA LOCAL ===',
        'A: OPERACIONAL PRINCIPAL; B: LABORATORIO, SEM PROVA TRANSFERIDA.',
        'BRIDGE: fonte Rust revisada; Client ID no CODIGO identificado; runtime nao comprovado.',
        '  possiveis processos multiprotocol: ' + readable(count_bridge),
        'LAB: scripts CLI encontrados: ' + str(sum(lab['cli_script_files_present'].values())) + '/2;',
        '  operadores reais e politica para A nao comprovados.',
        '  possiveis mosquitto_pub/sub: ' + readable(count_pub) + '/' + readable(count_sub),
        'SENSOR02: script de testes presente=' + str(sensor['device_test_script_file_present']).lower() +
        '; dispositivo remoto nao examinado.',
        'C.6: referencias existentes por identidade (somente quantidades): ' +
        ', '.join(i + '=' + str(model['c6_indexed_reference_counts'][i]) for i in c.ACCOUNTS) + '.',
        'C-V1: 21 pendencias preservadas; NENHUMA baixa automatica.',
        'LIMITES: valores de credenciais nao sao exibidos nem persistidos; sem conexao MQTT nem prova de implantacao.',
        'GATES: Seguranca, Git/CI, operacao e janela continuam pendentes.',
        'RESULTADO: DOSSIE PASSIVO, NAO APROVACAO; CORTE 8883 NAO AUTORIZADO.',
    ]
    return '\n'.join(lines)


def plan() -> str:
    return '\n'.join([
        '=== C.7 — COLETA DOCUMENTAL REAL (CENARIO A) ===',
        '1 BRIDGE: comprovante redigido do processo/servico real, parametros efetivos TLS e Client ID;',
        '  capturar sem cmdline/environ, sem credenciais, e verificar em homologacao.',
        '2 LAB: identificar se CLI e usado por operador/servico real; documentar politica aprovada',
        '  de IDs/contas e ACL minima antes de registrar evidencia operacional.',
        '3 SENSOR02: identificar firmware, host ou servico e Client ID efetivo por inventario autorizado;',
        '  se nao implantado, comprovar nao implantacao e submeter exclusao formal ao escopo.',
        '4 CREDENCIAIS: custodiante/canal autenticado/rotacao/retorno sem registrar segredos neste chat.',
        '5 ROLLBACK: troca e reconexao de CADA cliente real em ambiente isolado.',
        '6 Revisar e redigir documentos FORA deste coletor; indexar no C.6 somente com referencia opaca',
        '  e hash do documento redigido, sempre como pending-independent-review.',
        '7 Seguranca e Git/CI: deliberacoes independentes; janela e snapshot final somente depois.',
        'NAO EXECUTAR: Mosquitto original, reativacao de sensor01, Git push, ACL, rotacao ou corte.',
        'RESULTADO: evidencias ainda dependem de comprovacao; 21 pendencias abertas.',
    ])


def verified_context(project: Path, snapshot: Path, private: Path,
                     backups: Path, plugin: Path) -> tuple[c5.Context, dict]:
    ctx = c5.verified_context(project, snapshot, private, backups, plugin)
    require(len(ctx.pending) == PENDING_REQUIRED,
            'pendencias diferentes de 21; avaliar manualmente antes da C.7')
    index = c6.read_index(private, ctx.fingerprint)
    c6.validate(index, ctx.fingerprint)
    return ctx, index


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('--snapshot', required=True, type=Path)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--backups-root', type=Path,
                        default=Path.home() / 'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    args = parser.parse_args(argv)
    try:
        require(os.geteuid() != 0, 'nao executar como root')
        project, snapshot, private, backups, plugin = (
            p.absolute() for p in (args.project_root, args.snapshot,
                                    args.private_root, args.backups_root, args.plugin_path))
        ctx, index = verified_context(project, snapshot, private, backups, plugin)
        if args.action == 'preflight':
            print('APROVADO: baseline, C-v1/C-v2/C.6, branch e fontes conferidos.')
            print('C-V1: 21 pendencias; CORTE 8883 NAO AUTORIZADO.')
        elif args.action == 'coletar':
            report = collect(project, ctx, index)
            write_once(private, report, ctx.fingerprint)
            print('APROVADO: coleta PASSIVA C.7 gravada em arquivo privado separado, modo 0600.')
            print(safe_summary(read_collection(private, ctx.fingerprint), ctx.fingerprint))
        elif args.action == 'verificar':
            read_collection(private, ctx.fingerprint)
            print('APROVADO: arquivo privado C.7, estrutura e vinculo do snapshot validados.')
            print('C-V1: 21 pendencias; C-v2 e C.6 nao alterados; CORTE 8883 NAO AUTORIZADO.')
        elif args.action == 'resumo':
            print(safe_summary(read_collection(private, ctx.fingerprint), ctx.fingerprint))
        else:
            print(plan())
        return 0
    except (Block, c6.Block, c5.Block, c4.Block, c3.Block, c.Block, p2.Block,
            ValueError, OSError, TypeError, UnicodeError):
        print('BLOQUEIO: baseline, indice ou coleta C.7 invalidos; '
              'nenhuma alteracao MQTT ou de prontidao. CORTE 8883 NAO AUTORIZADO.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
