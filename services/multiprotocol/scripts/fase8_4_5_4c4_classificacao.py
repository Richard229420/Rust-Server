#!/usr/bin/env python3
"""Fase 8.4.5.4-C.4: matriz A/B de clientes MQTT, SEM CORTE.

Extensao lateral privada do cadastro C-v1. Preserva o cadastro original, as
chaves, os brokers, os snapshots, as politicas ACL e a governanca Git/CI.
Estados de implantacao aqui sao DECLARACOES, nunca prova de cliente real.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
import re
import sys

import fase8_4_5_2_preparar as p2
import fase8_4_5_4c_prontidao_corte as c
import fase8_4_5_4c3_evidencias as c3

PHASE = '8.4.5.4-C.4'
SCHEMA = 2
FILENAME = 'classificacao-clientes-c4.json'
SCENARIOS = ('A', 'B')
ROLES = {'A': 'operational-primary', 'B': 'laboratory-secondary'}
# Declaracao de arquitetura, NAO inventario de clientes efetivamente implantados.
PLANS = {
    'A': {
        'lab': ('cli-temporary', 'security-review-pending'),
        'bridge': ('persistent', 'fixed'),
        'device-sensor02': ('persistent', 'fixed'),
    },
    'B': {
        'lab': ('cli-temporary', 'dynamic-cli'),
        'bridge': ('persistent', 'fixed'),
        'device-sensor02': ('persistent', 'fixed'),
    },
}
DEPLOYMENTS = ('unknown', 'declared-deployed', 'declared-not-deployed')
EVIDENCE_KINDS = ('service-config', 'device-config', 'deployment-inventory',
                  'operator-attestation', 'lab-log')
REFERENCE = re.compile(r'\A[A-Za-z][A-Za-z0-9._:-]{3,95}\Z')
FORBIDDEN = ('password', 'passwd', 'secret', 'token', 'senha', 'private', 'chave',
             'credential', 'credencial', '-----begin')
GATES = ('security', 'git_ci', 'operational_readiness')
LAB_A_PROPOSALS = ('fixed-per-instance-proposed', 'dynamic-cli-proposed')
MAX_BYTES = 32 * 1024


class Block(Exception):
    """Erro sem dados privados enviados em linha de comando ou cadastro."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise Block(message)


def template(fingerprint: str) -> dict:
    need(bool(re.fullmatch(r'[a-f0-9]{64}', fingerprint)), 'snapshot invalido')
    return {
        'schema': SCHEMA,
        'phase': PHASE,
        'snapshot_manifest_sha256': fingerprint,
        'cutover_authorized': False,
        'gates': {name: False for name in GATES},
        'scenarios': {
            scenario: {
                'role': ROLES[scenario],
                'identities': {
                    name: {
                        'client_class': PLANS[scenario][name][0],
                        'client_id_policy': PLANS[scenario][name][1],
                        'deployment': 'unknown',
                        'evidence_kind': '',
                        'evidence_ref': '',
                    }
                    for name in c.ACCOUNTS
                },
            }
            for scenario in SCENARIOS
        },
    }


def safe_reference(reference: str) -> bool:
    return (isinstance(reference, str) and REFERENCE.fullmatch(reference) is not None
            and not any(part in reference.casefold() for part in FORBIDDEN))


def validate(model: dict, fingerprint: str) -> None:
    need(isinstance(model, dict) and
         set(model) == {'schema', 'phase', 'snapshot_manifest_sha256',
                        'cutover_authorized', 'gates', 'scenarios'},
         'estrutura de classificacao desconhecida')
    need(type(model['schema']) is int and model['schema'] == SCHEMA and
         model['phase'] == PHASE and
         model['snapshot_manifest_sha256'] == fingerprint and
         model['cutover_authorized'] is False,
         'cadastro nao confere com snapshot ou declara corte autorizado')
    gates = model['gates']
    need(isinstance(gates, dict) and set(gates) == set(GATES) and
         all(value is False for value in gates.values()),
         'aprovacao externa deve permanecer indisponivel na C.4')
    scenarios = model['scenarios']
    need(isinstance(scenarios, dict) and set(scenarios) == set(SCENARIOS),
         'cenario ausente ou indevido')
    for scenario in SCENARIOS:
        entry = scenarios[scenario]
        need(isinstance(entry, dict) and set(entry) == {'role', 'identities'} and
             entry['role'] == ROLES[scenario], 'papel de cenario incorreto')
        identities = entry['identities']
        need(isinstance(identities, dict) and set(identities) == set(c.ACCOUNTS),
             'identidades extras ou ausentes')
        for name in c.ACCOUNTS:
            record = identities[name]
            need(isinstance(record, dict) and
                 set(record) == {'client_class', 'client_id_policy', 'deployment',
                                 'evidence_kind', 'evidence_ref'},
                 'campos inesperados na identidade')
            planned = PLANS[scenario][name]
            allowed_policy = (planned[1], *LAB_A_PROPOSALS) if (scenario, name) == ('A', 'lab') else (planned[1],)
            need(record['client_class'] == planned[0] and
                 record['client_id_policy'] in allowed_policy,
                 'estrategia de IDs diverge do plano; exige revisao externa')
            state, kind, ref = (record['deployment'], record['evidence_kind'],
                                record['evidence_ref'])
            need(type(state) is str and state in DEPLOYMENTS and
                 type(kind) is str and type(ref) is str,
                 'estado ou referencia malformados')
            if state == 'unknown':
                need(kind == '' and ref == '', 'evidencia sem estado declarado')
            else:
                need(kind in EVIDENCE_KINDS and safe_reference(ref),
                     'estado declarado exige tipo e referencia segura')


def reviewed_legacy(legacy: dict, fingerprint: str) -> list[str]:
    """Nao modifica nem reinterpreta as confirmacoes do C-v1."""
    pending, _ = c.validate_model(legacy, fingerprint)
    entries = {row['username']: row for row in legacy['identities']}
    bridge = entries['bridge']
    need(bridge['client_id'] == c3.BRIDGE_ID and
         bridge['evidence_kind'] == c3.BRIDGE_SOURCE_KIND and
         bridge['evidence_ref'] == c3.BRIDGE_REFERENCE,
         'registro estatico C.3 da bridge ausente ou divergente')
    return pending


def registry_path(root: Path) -> Path:
    return c.private_folder(root, create=False) / FILENAME


def read_registry(root: Path, fingerprint: str) -> dict:
    path = registry_path(root)
    try:
        raw = p2.check_regular(path, private=True, limit=MAX_BYTES)
        doc = json.loads(raw)
    except (OSError, ValueError, UnicodeError, p2.Block):
        raise Block('classificacao C.4 ausente, insegura ou corrompida') from None
    validate(doc, fingerprint)
    return doc


def create_registry(root: Path, fingerprint: str) -> Path:
    path = registry_path(root)
    need(not path.exists() and not path.is_symlink(),
         'classificacao C.4 ja existe: nao sobrescrever')
    doc = template(fingerprint)
    validate(doc, fingerprint)
    payload = (json.dumps(doc, indent=2, ensure_ascii=False) + '\n').encode()
    try:
        p2.write_exclusive(path, payload)
        p2.check_regular(path, private=True, limit=MAX_BYTES)
    except (OSError, p2.Block):
        raise Block('falha ao criar classificacao privada') from None
    return path


def update_declaration(model: dict, fingerprint: str, *, scenario: str,
                       identity: str, state: str, kind: str, reference: str) -> dict:
    validate(model, fingerprint)
    need(scenario in SCENARIOS and identity in c.ACCOUNTS,
         'cenario ou identidade nao reconhecidos')
    need(state in DEPLOYMENTS[1:] and kind in EVIDENCE_KINDS and safe_reference(reference),
         'declaracao exige estado, tipo e referencia segura')
    # Nunca reinterpreta declaracoes conflitantes nem apaga evidencia.
    result = copy.deepcopy(model)
    row = result['scenarios'][scenario]['identities'][identity]
    if row['deployment'] != 'unknown':
        need((row['deployment'], row['evidence_kind'], row['evidence_ref']) ==
             (state, kind, reference), 'declaracao anterior divergente; revisao manual necessaria')
    row.update({'deployment': state, 'evidence_kind': kind, 'evidence_ref': reference})
    validate(result, fingerprint)
    return result



def propose_lab_policy(model: dict, fingerprint: str, proposal: str) -> dict:
    """Apenas proposta arquitetural da conta lab em A; nao aprova ACL ou Seguranca."""
    validate(model, fingerprint)
    need(proposal in LAB_A_PROPOSALS, 'politica proposta invalida')
    result = copy.deepcopy(model)
    row = result['scenarios']['A']['identities']['lab']
    old = row['client_id_policy']
    need(old in ('security-review-pending', proposal),
         'proposta anterior divergente; revisao humana necessaria')
    row['client_id_policy'] = proposal
    validate(result, fingerprint)
    return result


def save_declaration(root: Path, original: dict, updated: dict, fingerprint: str) -> bool:
    validate(original, fingerprint)
    validate(updated, fingerprint)
    path = registry_path(root)
    raw, metadata = c3.secured_original(path)
    try:
        actual = json.loads(raw)
    except (ValueError, UnicodeError):
        raise Block('classificacao alterada ou invalida') from None
    need(actual == original, 'classificacao alterada desde a leitura')
    # Usa a mesma gravacao atomica com checagem de inode/mode/hash da C.3.
    return c3.atomic_save_model(path, raw, metadata, updated)


def summarize(model: dict, fingerprint: str, pending: list[str]) -> None:
    validate(model, fingerprint)
    print('=== RUST-SERVER 8.4.5.4-C.4 — CENARIOS A/B SEM CORTE ===')
    print('A: OPERACIONAL PRINCIPAL; B: LABORATORIO E HOMOLOGACAO COMPLEMENTARES.')
    for scenario in SCENARIOS:
        print('CENARIO ' + scenario + ':')
        for name in c.ACCOUNTS:
            record = model['scenarios'][scenario]['identities'][name]
            # Nao exibir referencia livre nem caminho/segredo do operador.
            marker = 'referencia-registrada' if record['evidence_ref'] else 'sem-evidencia'
            print('  ' + name + ': classe=' + record['client_class'] +
                  ', politica=' + record['client_id_policy'] +
                  ', implantacao=' + record['deployment'] + ', ' + marker)
    print('REVOGADO: device-sensor01 nao consta dos dois cadastros.')
    print('C-V1: ' + str(len(pending)) + ' pendencias originais; SEM BAIXA AUTOMATICA.')
    print('LIMITES: declaracao de implantacao NAO comprova execucao, troca, rollback ou ACL real.')
    print('BLOQUEIOS: revisoes independentes de Seguranca, Git/CI, prontidao e janela.')
    print('RESULTADO: classificacao de arquitetura; CORTE 8883 NAO AUTORIZADO.')


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('preflight', 'criar', 'matriz', 'registrar', 'propor-politica-lab'))
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--backups-root', type=Path,
                        default=Path.home() / 'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    parser.add_argument('--cenario', choices=SCENARIOS)
    parser.add_argument('--identidade', choices=c.ACCOUNTS)
    parser.add_argument('--estado', choices=DEPLOYMENTS[1:])
    parser.add_argument('--tipo-evidencia', choices=EVIDENCE_KINDS)
    parser.add_argument('--referencia')
    parser.add_argument('--politica', choices=LAB_A_PROPOSALS)
    args = parser.parse_args(argv)
    try:
        project, snapshot, private, backups, plugin = (p.absolute() for p in
              (args.project_root, args.snapshot, args.private_root,
               args.backups_root, args.plugin_path))
        c.verify_branch(project)
        fingerprint, _ = c.baseline(snapshot, backups, project, private, plugin)
        c3.verify_bridge_source(project)
        legacy = c.load_model(private)
        pending = reviewed_legacy(legacy, fingerprint)
        fields = (args.cenario, args.identidade, args.estado,
                  args.tipo_evidencia, args.referencia)
        if args.action == 'registrar':
            need(all(fields) and args.politica is None, 'registro incompleto ou argumentos indevidos')
        elif args.action == 'propor-politica-lab':
            need(not any(fields) and args.politica in LAB_A_PROPOSALS,
                 'proposta incompleta ou argumentos indevidos')
        else:
            need(not any(fields) and args.politica is None,
                 'argumentos de declaracao nao se aplicam a esta acao')
        if args.action == 'preflight':
            print('APROVADO: branch, snapshot, politica, fontes e C-v1 conferidos.')
            print('C-V1: ' + str(len(pending)) + ' pendencias; CORTE 8883 NAO AUTORIZADO.')
        elif args.action == 'criar':
            create_registry(private, fingerprint)
            doc = read_registry(private, fingerprint)
            print('APROVADO: classificacao A/B criada em arquivo PRIVADO separado; C-v1 intacto.')
            summarize(doc, fingerprint, pending)
        elif args.action == 'matriz':
            summarize(read_registry(private, fingerprint), fingerprint, pending)
        else:
            old = read_registry(private, fingerprint)
            if args.action == 'registrar':
                new = update_declaration(old, fingerprint, scenario=args.cenario,
                                         identity=args.identidade, state=args.estado,
                                         kind=args.tipo_evidencia, reference=args.referencia)
            else:
                new = propose_lab_policy(old, fingerprint, args.politica)
            changed = save_declaration(private, old, new, fingerprint)
            print('DECLARACAO DOCUMENTADA; NAO E COMPROVACAO OPERACIONAL OU APROVACAO DE SEGURANCA.'
                  if changed else 'DECLARACAO IDENTICA JA EXISTE (nenhuma alteracao).')
            summarize(read_registry(private, fingerprint), fingerprint, pending)
        return 0
    except (Block, c.Block, c3.Block, p2.Block, ValueError, TypeError, OSError):
        print('BLOQUEIO: cadastro, branch, fonte ou snapshot nao validado; '
              'nenhum broker alterado. CORTE 8883 NAO AUTORIZADO.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(cli())
