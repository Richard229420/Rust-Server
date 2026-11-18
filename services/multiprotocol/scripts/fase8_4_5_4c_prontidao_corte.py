#!/usr/bin/env python3
"""Rust-Server Fase 8.4.5.4-C: cadastro privado e plano de prontidao SEM CORTE.

Nenhum subprocesso de provisionamento, comando MQTT, alteracao de credenciais,
reinicio de broker, restauracao, commit ou mudanca de branch ocorre aqui.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

import fase8_4_5_2_preparar as phase2
import fase8_4_5_3_ensaio as phase3
import fase8_4_5_4b_paridade_producao as phase4b

BRANCH = 'feature/fase8-4-inventory-dynsec'
SCHEMA = 1
PHASE = '8.4.5.4-C'
ACCOUNTS = ('lab', 'bridge', 'device-sensor02')
EXCLUDED = ('device-sensor01', 'lab84-bridge', 'lab84-admin')
FILENAME = 'cadastro-prontidao.json'
SOURCE_KINDS = ('service-config', 'application-code', 'device-config', 'runtime-observation')
TOKEN = re.compile(r'\A[A-Za-z0-9._:-]{4,96}\Z')
CLIENT_ID = re.compile(r'\A[A-Za-z0-9._:-]{1,128}\Z')
GLOBAL_CHECKS = (
    'canal_distribuicao_secreta_definido',
    'procedimento_rotacao_documentado',
    'reconfiguracao_cliente_testada_fora_de_producao',
    'rollback_reconexao_testado_fora_de_producao',
    'janela_e_responsaveis_definidos',
    'monitoramento_e_criterios_aborto_definidos',
)
ACCOUNT_CHECKS = ('client_id_confirmado', 'cliente_suporta_troca_credencial',
                  'retorno_credencial_legada_planejado')


class Block(Exception):
    """Excecoes sem dados privados, caminhos ou valores fornecidos pelo usuario."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Block(message)


def manifest_fingerprint(snapshot: Path) -> str:
    return hashlib.sha256(phase2.check_regular(snapshot / phase2.NAME, private=True)).hexdigest()


def verify_branch(project: Path) -> None:
    require(os.geteuid() != 0, 'nao execute como root/sudo')
    try:
        r = subprocess.run(['git', '-C', str(project), 'branch', '--show-current'],
                           capture_output=True, text=True, timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Block('branch Git nao verificavel') from None
    require(r.returncode == 0 and r.stdout.strip() == BRANCH,
            'branch diferente da fase 8.4 (nada foi alterado)')


def baseline(snapshot: Path, backups: Path, project: Path, root: Path,
             plugin: Path) -> tuple[str, dict]:
    """Validacao som. leitura sem depender de broker ativo nem portas temporarias."""
    phase3.paths_ok(snapshot, backups, project, root)
    require(plugin.is_file() and not plugin.is_symlink(), 'plugin DynSec ausente')
    phase2.verify(snapshot, plugin)
    phase3.assert_origins_match(snapshot, project, root)
    mapping = phase4b.verify_plan(snapshot, plugin)
    require(set(mapping) == set(ACCOUNTS), 'identidades divergentes do baseline')
    require(all(mapping[name] for name in ACCOUNTS), 'ACLs incompletas')
    require('device-sensor01' not in mapping, 'identidade revogada no baseline')
    return manifest_fingerprint(snapshot), mapping


def template(fingerprint: str) -> dict:
    require(bool(re.fullmatch(r'[a-f0-9]{64}', fingerprint)), 'identificador de snapshot invalido')
    return {
        'schema': SCHEMA,
        'phase': PHASE,
        'cutover_authorized': False,
        'snapshot_manifest_sha256': fingerprint,
        'identities': [
            {'username': name, 'client_id': '', 'evidence_kind': '', 'evidence_ref': '',
             'client_id_confirmado': False, 'cliente_suporta_troca_credencial': False,
             'retorno_credencial_legada_planejado': False}
            for name in ACCOUNTS
        ],
        'readiness': {key: False for key in GLOBAL_CHECKS},
    }


def private_folder(root: Path, *, create: bool) -> Path:
    try:
        phase2.secure_dir(root)
        folder = root / 'phase8-4-5-4c'
        if not folder.exists() and not folder.is_symlink():
            require(create, 'cadastro privado ausente; execute modelo')
            folder.mkdir(mode=0o700)
        phase2.secure_dir(folder)
        require(folder.parent == root and not folder.is_symlink(), 'caminho privado invalido')
        return folder
    except phase2.Block:
        raise Block('diretorio privado inseguro') from None


def create_model(root: Path, fingerprint: str) -> Path:
    folder = private_folder(root, create=True)
    destination = folder / FILENAME
    require(not destination.exists() and not destination.is_symlink(),
            'cadastro ja existe; nao sobrescrever nem repetir modelo')
    encoded = (json.dumps(template(fingerprint), indent=2, sort_keys=False,
                          ensure_ascii=False) + '\n').encode('utf-8')
    try:
        phase2.write_exclusive(destination, encoded)
        phase2.check_regular(destination, private=True, limit=32 * 1024)
    except phase2.Block:
        raise Block('falha na gravacao privada do cadastro') from None
    return destination


def load_model(root: Path) -> dict:
    folder = private_folder(root, create=False)
    try:
        data = phase2.check_regular(folder / FILENAME, private=True, limit=32 * 1024)
    except phase2.Block:
        raise Block('cadastro privado ausente ou inseguro') from None
    try:
        parsed = json.loads(data)
    except (ValueError, UnicodeError):
        raise Block('cadastro privado com JSON invalido') from None
    require(isinstance(parsed, dict), 'cadastro nao e objeto JSON')
    return parsed


def valid_client_id(cid: str) -> bool:
    return (isinstance(cid, str) and CLIENT_ID.fullmatch(cid) is not None
            and not cid.lower().startswith(('lab84-', 'phase845', 'phase8-'))
            and cid not in ('auto', 'random', 'unknown', 'desconhecido'))


def validate_model(model: dict, expected_fp: str) -> tuple[list[str], list[str]]:
    """Estrutura invalida=Block; falta de evidencia=pendencia, nunca corte automatico."""
    require(set(model) == {'schema', 'phase', 'cutover_authorized',
                           'snapshot_manifest_sha256', 'identities', 'readiness'},
            'campos inesperados no cadastro')
    require(model['schema'] == SCHEMA and model['phase'] == PHASE and
            model['cutover_authorized'] is False and
            model['snapshot_manifest_sha256'] == expected_fp,
            'cadastro nao vinculado ao snapshot ou autorizacao indevida')
    records = model['identities']
    require(isinstance(records, list) and len(records) == len(ACCOUNTS),
            'quantidade de identidades incorreta')
    require(all(isinstance(entry, dict) for entry in records), 'registro de identidade invalido')
    usernames = [entry.get('username') for entry in records]
    require(set(usernames) == set(ACCOUNTS) and len(set(usernames)) == len(usernames),
            'conta adicional, revogada, duplicada ou ausente')
    readiness = model['readiness']
    require(isinstance(readiness, dict) and set(readiness) == set(GLOBAL_CHECKS),
            'estrutura de criterios gerais invalida')
    require(all(type(value) is bool for value in readiness.values()),
            'criterios gerais exigem booleanos')
    pendings: list[str] = []
    confirmed_ids: list[str] = []
    for entry in records:
        require(set(entry) == {'username', 'client_id', 'evidence_kind', 'evidence_ref',
                               *ACCOUNT_CHECKS}, 'campos inesperados na identidade')
        username = entry['username']
        cid = entry['client_id']
        require(isinstance(cid, str) and len(cid) <= 128,
                'Client ID invalido ou longo demais')
        if cid:
            require(valid_client_id(cid), 'Client ID invalido ou de ensaio')
            confirmed_ids.append(cid)
        else:
            pendings.append('Client ID real nao registrado: ' + username)
        kind = entry['evidence_kind']
        ref = entry['evidence_ref']
        require(isinstance(kind, str) and isinstance(ref, str), 'evidencia malformada')
        if kind:
            require(kind in SOURCE_KINDS, 'categoria de evidencia desconhecida')
        else:
            pendings.append('origem do Client ID nao registrada: ' + username)
        if ref:
            require(TOKEN.fullmatch(ref) is not None, 'referencia de evidencia invalida')
        else:
            pendings.append('evidencia verificavel pendente: ' + username)
        for key in ACCOUNT_CHECKS:
            require(type(entry[key]) is bool, 'campo de confirmacao nao booleano')
            if not entry[key]:
                pendings.append('confirmacao pendente (' + username + '): ' + key)
        # Do not accept arbitrary/client-generated IDs as verified even if flags set.
        if entry['client_id_confirmado'] and not (cid and kind and ref):
            raise Block('identidade marcada como confirmada sem fonte documentada')
    require(len(set(confirmed_ids)) == len(confirmed_ids), 'Client IDs duplicados')
    for key in GLOBAL_CHECKS:
        if not readiness[key]:
            pendings.append('criterio operacional pendente: ' + key)
    warnings = [
        'A verificacao do cadastro e declarativa; nao comprova a configuracao real dos clientes.',
        'Aprovacoes Git/CI e de Seguranca sao externas e continuam obrigatorias.',
        'Um snapshot antigo nao substitui a captura final sob janela de manutencao.',
        'O rollback real 8883 nao foi executado e o corte permanece proibido.',
    ]
    return pendings, warnings


def show_plan(mapping: dict) -> None:
    print('=== FASE 8.4.5.4-C: PLANO DE CORTE, SOMENTE PREPARACAO ===')
    for user in ACCOUNTS:
        acl = mapping[user]
        print(f'BASELINE: {user}: {len(acl)} permissoes DynSec equivalentes; '
              'Client ID real A CONFIRMAR.')
    print('EXCLUIDO: sensor01 revogado; jamais criar ou habilitar no candidato.')
    print('SEQUENCIA FUTURA: validar IDs estaveis nos clientes reais -> gerar credenciais novas em cofre privado')
    print(' -> testar configuracao alternativa em ambiente isolado -> distribuir por canal autenticado')
    print(' -> obter janela/CI/auditoria -> capturar backup final -> corte controlado -> verificacao -> rollback se necessario.')
    print('ROLLBACK: manter hashes e credenciais legadas disponiveis com acesso restrito ate fechar a janela;')
    print(' nao invalidar senhas legadas antes de encerrar a janela de reversao.')
    print('PROIBIDO: reaproveitar senhas de laboratorio, imprimir segredos, sobrescrever 8883/8884,')
    print(' realizar cutover automatico ou interpretar este plano como autorizacao de seguranca.')


def cli() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('preflight', 'plano', 'modelo', 'avaliar'))
    parser.add_argument('--snapshot', required=True, type=Path)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home()/'.config/rust-server')
    parser.add_argument('--backups-root', type=Path, default=Path.home()/'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=phase2.PLUGIN)
    args = parser.parse_args()
    try:
        snapshot, backups, project, root, plugin = [p.absolute() for p in
               (args.snapshot, args.backups_root, args.project_root,
                args.private_root, args.plugin_path)]
        verify_branch(project)
        fingerprint, mapping = baseline(snapshot, backups, project, root, plugin)
        if args.action == 'preflight':
            print('APROVADO: branch, baseline legado, ACLs e snapshot 8.4.5.2 verificados (somente leitura).')
            print('PENDENTE: Client IDs e distribuicao de credenciais reais; corte 8883 NAO AUTORIZADO.')
        elif args.action == 'plano':
            show_plan(mapping)
        elif args.action == 'modelo':
            path = create_model(root, fingerprint)
            print('APROVADO: modelo privado de cadastro criado; nao contem credenciais.')
            print('CADASTRO=' + str(path))
            print('PENDENTE: preencher Client IDs com evidencias reais; corte 8883 NAO AUTORIZADO.')
        else:
            model = load_model(root)
            pending, warnings = validate_model(model, fingerprint)
            print('=== FASE 8.4.5.4-C: AVALIACAO DECLARATIVA, SEM CORTE ===')
            for item in pending:
                print('PENDENTE: ' + item)
            for item in warnings:
                print('LIMITE: ' + item)
            if pending:
                print(f'RESULTADO: {len(pending)} pendencias de prontidao; corte 8883 NAO AUTORIZADO.')
                return 3
            print('RESULTADO: CADASTRO COMPLETO PARA REVISAO MANUAL; corte 8883 NAO AUTORIZADO.')
        return 0
    except (Block, phase2.Block, phase3.Block, phase4b.Block):
        print('BLOQUEIO: branch, baseline, snapshot ou cadastro nao validado; nenhum broker alterado.',
              file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, UnicodeError):
        print('BLOQUEIO: falha de E/S ou documento invalido, detalhes privados omitidos.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(cli())
