#!/usr/bin/env python3
"""Fase 8.4.5.5-A.2: reconciliacao PKI por snapshot CANDIDATO, SEM CORTE.

Nunca altera origens, snapshot historico, cadastros C, broker, Git ou credenciais.
Apenas 'criar' faz copias privadas, exclusivamente em ~/server_backups/fase8_4_5_5a2.
Nao contorna verificacao de origem da 8.4.5.3 nem habilita a 8.4.5.5-A.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import subprocess
import sys
import tempfile

import fase8_4_5_2_preparar as p2
import fase8_4_5_4c_prontidao_corte as c
import fase8_4_5_4c4_classificacao as c4
import fase8_4_5_4c6_inventario_operacional as c6
import fase8_4_5_4c7_coleta_evidencias as c7

PHASE = '8.4.5.5-A.2'
NAME = 'reconciliacao-pki.json'
SCHEMA = 1
MAX_MANIFEST = 48 * 1024
MAX_CERT = 256 * 1024
EXPECTED_CHANGED = frozenset({
    'lab/pki/ca.crt', 'lab/pki/server.crt', 'lab/pki/server.key',
})
ACTIONS = ('preflight', 'inspecionar', 'criar', 'verificar', 'plano')
SHA = re.compile(r'\A[a-f0-9]{64}\Z')
CANDIDATE_PREFIX = 'candidato-'
REQUIRED_PENDING = 21


class Block(Exception):
    """Nenhum dado de arquivo ou segredo em mensagens de falha."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise Block(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_bytes(project: Path, private: Path) -> dict[str, bytes]:
    out: dict[str, bytes] = {}
    for label, path in p2.sources(project, private).items():
        out[label] = p2.check_regular(path, private=p2.SPECS[label][1])
    return out


def historic_bytes(snapshot: Path) -> dict[str, bytes]:
    return {label: p2.check_regular(snapshot / 'files' / label, private=True)
            for label in p2.SPECS}


def delta(old: dict[str, bytes], new: dict[str, bytes]) -> tuple[str, ...]:
    need(set(old) == set(p2.SPECS) == set(new), 'inventario incompleto')
    return tuple(sorted(name for name in p2.SPECS if sha(old[name]) != sha(new[name])))


def run_openssl(args: list[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        process = subprocess.run(
            ['openssl', *args], input=input_bytes, capture_output=True,
            timeout=12, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise Block('ferramenta TLS indisponivel') from None
    need(process.returncode == 0, 'verificacao TLS nao aprovada')
    return process.stdout


def tls_checks(ca: bytes, certificate: bytes, key: bytes) -> None:
    """Compara dados lidos sob O_NOFOLLOW; sem publicar chave ou openssl stderr.

    openssl verify usa CA e cert temporarios em diretorio privado 0700 e nao
    usa os caminhos vivos, prevenindo troca dos arquivos entre leitura e check.
    """
    need(all(0 < len(x) <= MAX_CERT for x in (ca, certificate, key)),
         'material PKI em tamanho inesperado')
    with tempfile.TemporaryDirectory(prefix='rust-server-pki-check-') as location:
        scratch = Path(location)
        os.chmod(scratch, 0o700)
        ca_path, cert_path = scratch / 'ca.crt', scratch / 'server.crt'
        p2.write_exclusive(ca_path, ca)
        p2.write_exclusive(cert_path, certificate)
        for opts in (
            ['verify', '-purpose', 'sslserver', '-CAfile', str(ca_path), str(cert_path)],
            ['verify', '-purpose', 'sslserver', '-verify_hostname', 'localhost',
             '-CAfile', str(ca_path), str(cert_path)],
            ['verify', '-purpose', 'sslserver', '-verify_ip', '127.0.0.1',
             '-CAfile', str(ca_path), str(cert_path)],
        ):
            run_openssl(opts)
        run_openssl(['x509', '-noout', '-checkend', '0'], input_bytes=certificate)
        public_cert = run_openssl(['x509', '-pubkey', '-noout'], input_bytes=certificate)
        public_cert_der = run_openssl(['pkey', '-pubin', '-outform', 'DER'],
                                      input_bytes=public_cert)
        public_key_der = run_openssl(['pkey', '-pubout', '-outform', 'DER'], input_bytes=key)
        need(public_cert_der == public_key_der, 'chave e certificado nao correspondem')


def verify_historical_and_registries(project: Path, private: Path, snapshot: Path,
                                     backup_old: Path, plugin: Path) -> str:
    """Confere o historico e cadastros pelo FP antigo, SEM exigir origens iguais."""
    need(os.geteuid() != 0, 'nao executar com sudo/root')
    need(snapshot.is_absolute() and snapshot.parent == backup_old and
         snapshot.name.startswith('snapshot-') and not snapshot.is_symlink(),
         'snapshot historico fora do local esperado')
    p2.backup_root_ok(backup_old, project, private, Path.home(), create=False)
    need(plugin.is_file() and not plugin.is_symlink(), 'plugin DynSec indisponivel')
    p2.verify(snapshot, plugin)
    c.verify_branch(project)
    fp = c.manifest_fingerprint(snapshot)
    legacy = c.load_model(private)
    pending = c4.reviewed_legacy(legacy, fp)
    need(len(pending) == REQUIRED_PENDING, 'contagem C-v1 diferente de 21')
    c4.read_registry(private, fp)
    c6.read_index(private, fp)
    c7.read_collection(private, fp)
    return fp


def inspect(project: Path, private: Path, snapshot: Path, backup_old: Path,
            plugin: Path) -> tuple[str, dict[str, bytes], dict[str, bytes]]:
    fp = verify_historical_and_registries(project, private, snapshot, backup_old, plugin)
    historic, current = historic_bytes(snapshot), source_bytes(project, private)
    need(set(delta(historic, current)) == EXPECTED_CHANGED,
         'divergencias fora das tres entradas PKI esperadas')
    tls_checks(current['lab/pki/ca.crt'], current['lab/pki/server.crt'],
               current['lab/pki/server.key'])
    # Releitura: detectar rotacao de fontes durante o teste criptografico.
    refreshed = source_bytes(project, private)
    need(all(sha(source) == sha(refreshed[label])
             for label, source in current.items()),
         'fontes alteradas durante a verificacao')
    return fp, historic, current


def target_root_ok(root: Path, project: Path, private: Path, *, create: bool) -> None:
    need(root == Path.home() / 'server_backups/fase8_4_5_5a2',
         'destino deve ser o armazenamento privado dedicado A.2')
    p2.backup_root_ok(root, project, private, Path.home(), create=create)
    if create:
        p2.secure_dir(root)


def make_manifest(fp: str, old: dict[str, bytes], current: dict[str, bytes]) -> dict:
    need(SHA.fullmatch(fp) is not None and set(delta(old, current)) == EXPECTED_CHANGED,
         'delta ou vinculo historico invalido')
    return {
        'schema': SCHEMA,
        'phase': PHASE,
        'historic_snapshot_manifest_sha256': fp,
        'scenario_primary': 'A',
        'scenario_secondary': 'B',
        'status': 'candidate-unapproved',
        'purpose': 'pki-v2-reconciliation-review',
        'cutover_authorized': False,
        'decision': 'NO-GO',
        'external_approvals': {'security': False, 'git_ci': False, 'operations': False},
        'c_v1_pending': REQUIRED_PENDING,
        'ready_for_8455b': False,
        'historical_snapshot_replaced': False,
        'legacy_registries_migrated': False,
        'revoked_identity_unchanged': True,
        'final_maintenance_backup': False,
        'pki_provenance': 'pending-independent-review',
        'files': [
            {'name': name, 'size': len(current[name]), 'historic_sha256': sha(old[name]),
             'candidate_sha256': sha(current[name]),
             'status': 'changed-pki' if name in EXPECTED_CHANGED else 'identical'}
            for name in sorted(p2.SPECS)
        ],
    }


def validate_manifest(doc: object, fp: str) -> None:
    need(isinstance(doc, dict), 'manifesto invalido')
    expected_keys = set(make_manifest(fp, {x: b'a' for x in p2.SPECS},
                                      {x: (b'b' if x in EXPECTED_CHANGED else b'a')
                                       for x in p2.SPECS}))
    need(set(doc) == expected_keys, 'campos de manifesto divergentes')
    fields = ('schema', 'phase', 'historic_snapshot_manifest_sha256',
              'scenario_primary', 'scenario_secondary', 'status', 'purpose',
              'cutover_authorized', 'decision', 'external_approvals', 'c_v1_pending',
              'ready_for_8455b', 'historical_snapshot_replaced',
              'legacy_registries_migrated', 'revoked_identity_unchanged',
              'final_maintenance_backup', 'pki_provenance')
    expected = make_manifest(fp, {x: b'a' for x in p2.SPECS},
                             {x: (b'b' if x in EXPECTED_CHANGED else b'a')
                              for x in p2.SPECS})
    for key in fields:
        need(type(doc[key]) is type(expected[key]) and doc[key] == expected[key],
             'manifesto com aprovacao/estado indevido')
    need(type(doc['external_approvals']) is dict and
         set(doc['external_approvals']) == {'security', 'git_ci', 'operations'} and
         all(type(v) is bool and v is False
             for v in doc['external_approvals'].values()),
         'aprovacoes externas nao podem ser assumidas')
    files = doc['files']
    need(type(files) is list and len(files) == len(p2.SPECS),
         'inventario do manifesto invalido')
    need([f.get('name') for f in files if isinstance(f, dict)] == sorted(p2.SPECS),
         'ordem ou nomes das entradas divergentes')
    for rec in files:
        need(type(rec) is dict and set(rec) ==
             {'name', 'size', 'historic_sha256', 'candidate_sha256', 'status'},
             'campos de entrada invalidos')
        need(type(rec['size']) is int and 0 < rec['size'] <= p2.MAX_FILE and
             all(type(rec[k]) is str and SHA.fullmatch(rec[k]) is not None
                 for k in ('historic_sha256', 'candidate_sha256')),
             'hash/tamanho de entrada invalidos')
        label = rec['name']
        need(rec['status'] == ('changed-pki' if label in EXPECTED_CHANGED else 'identical') and
             (rec['historic_sha256'] != rec['candidate_sha256']) ==
             (label in EXPECTED_CHANGED), 'delta interno invalido')


def create(project: Path, private: Path, snapshot: Path, backup_old: Path,
           backup_new: Path, plugin: Path) -> Path:
    fp, old, current = inspect(project, private, snapshot, backup_old, plugin)
    target_root_ok(backup_new, project, private, create=True)
    need(not any(child.name.startswith(CANDIDATE_PREFIX)
                 for child in backup_new.iterdir()),
         'candidato A.2 ja existe; use verificar, nao recriar')
    final = backup_new / (CANDIDATE_PREFIX + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                          + '-' + secrets.token_hex(12))
    need(not final.exists() and not final.is_symlink(), 'colisao de destino')
    staging = Path(tempfile.mkdtemp(prefix='.incompleto-8455a2-', dir=backup_new))
    os.chmod(staging, 0o700)
    try:
        for label in sorted(p2.SPECS):
            p2.mkdirs_locked(staging, PurePosixPath('files') / PurePosixPath(label).parent)
            p2.write_exclusive(staging / 'files' / label, current[label])
        manifest = make_manifest(fp, old, current)
        encoded = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode('utf-8')
        need(len(encoded) <= MAX_MANIFEST, 'manifesto excedeu limite')
        p2.write_exclusive(staging / NAME, encoded)
        verify_candidate(staging, fp, old, check_name=False)
        # Restricao de estado original: nao aceitar rotacao entre captura e rename.
        need(all(sha(current[label]) == sha(source)
                 for label, source in source_bytes(project, private).items()),
             'origens mudaram durante captura')
        need(not final.exists() and not final.is_symlink(), 'destino existente')
        os.rename(staging, final)
        verify_candidate(final, fp, old)
        return final
    except Exception:
        # Nao apagar dados de uma copia parcial que pode conter segredos; manter 0700
        # para inspecao manual, NUNCA divulgar o caminho incompleto.
        raise


def verify_candidate(candidate: Path, fp: str, old: dict[str, bytes],
                     *, check_name: bool = True) -> dict:
    p2.secure_dir(candidate)
    if check_name:
        need(candidate.name.startswith(CANDIDATE_PREFIX) and
             candidate.parent == Path.home() / 'server_backups/fase8_4_5_5a2' and
             not candidate.is_symlink(), 'candidato em local inesperado')
    p2.secure_dir(candidate / 'files')
    raw = p2.check_regular(candidate / NAME, private=True, limit=MAX_MANIFEST)
    try:
        data = json.loads(raw)
    except (UnicodeError, ValueError):
        raise Block('manifesto nao legivel') from None
    validate_manifest(data, fp)
    new: dict[str, bytes] = {}
    for record in data['files']:
        label = record['name']
        payload = p2.check_regular(candidate / 'files' / label, private=True)
        parent = (candidate / 'files' / label).parent
        while parent != candidate:
            p2.secure_dir(parent)
            parent = parent.parent
        need(record['size'] == len(payload) and
             record['historic_sha256'] == sha(old[label]) and
             record['candidate_sha256'] == sha(payload),
             'integridade do candidato reprovada')
        new[label] = payload
    need(set(delta(old, new)) == EXPECTED_CHANGED, 'delta candidato divergente')
    tls_checks(new['lab/pki/ca.crt'], new['lab/pki/server.crt'],
               new['lab/pki/server.key'])
    return data


def messages() -> str:
    return '\n'.join([
        '=== FASE 8.4.5.5-A.2 — RECONCILIACAO PKI (SEM CORTE) ===',
        'Historico: snapshot 8.4.5.2 imutavel, 20 arquivos, usado como base.',
        'Exigido: 17 arquivos iguais + divergencias APENAS de ca.crt/server.crt/server.key do lab.',
        'TLS: cadeia, finalidade de servidor, localhost, 127.0.0.1 e chave correspondente.',
        'Candidato A.2: 20 copias privadas e manifesto proprio. NAO substitui baseline C-v1.',
        'ATENCAO: ca.key do laboratorio esta entre as 17 origens IGUAIS; nao foi atestada',
        '  a correspondencia dessa chave com a nova CA. Revisao separada obrigatoria.',
        'Origem da PKI v2 e autorizacao de Seguranca: ainda requerem evidencia independente.',
        'Proxima decisao: revisar proveniencia, fluxo formal de re-baseline e aprovacoes.',
        'A.5.5-A antigo: continua bloqueado se compara origens com snapshot de outubro.',
        'Nao usar candidato A.2 como --snapshot da 8.4.5.2 ou C-v1.',
        'Cenario A principal, B homologacao. 21 pendencias e NO-GO preservados.',
        'NAO EXECUTAR: broker, rotacao, git push, chmod, substituicao de snapshot ou corte 8883.',
    ])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('--snapshot', type=Path, required=False)
    parser.add_argument('--candidato', type=Path, required=False)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).absolute().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--backups-root', type=Path,
                        default=Path.home() / 'server_backups/fase8_4_5_2')
    parser.add_argument('--candidate-root', type=Path,
                        default=Path.home() / 'server_backups/fase8_4_5_5a2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    args = parser.parse_args(argv)
    try:
        need(args.snapshot is not None, 'informe --snapshot do historico')
        project, private, snapshot, backup_old, backup_new, plugin = (
            path.absolute() for path in
            (args.project_root, args.private_root, args.snapshot, args.backups_root,
             args.candidate_root, args.plugin_path))
        if args.action == 'plano':
            print(messages())
            return 0
        if args.action in ('preflight', 'inspecionar'):
            fp, old, current = inspect(project, private, snapshot, backup_old, plugin)
            target_root_ok(backup_new, project, private, create=False)
            need(set(delta(old, current)) == EXPECTED_CHANGED and SHA.fullmatch(fp) is not None,
                 'delta invalido')
            print('APROVADO: snapshot historico integro, 17 iguais e 3 PKI divergentes esperados.')
            print('APROVADO: cadeia TLS, finalidade, localhost, 127.0.0.1 e chave correspondente.')
            if args.action == 'inspecionar':
                for label in sorted(EXPECTED_CHANGED):
                    print('DIVERGENTE: ' + label)
            print('ALERTA: correspondencia de lab/pki/ca.key com CA atual NAO comprovada.')
            print('C-V1: 21 pendencias preservadas; PKI v2 ainda requer revisao de procedencia.')
        elif args.action == 'criar':
            dest = create(project, private, snapshot, backup_old, backup_new, plugin)
            print('APROVADO: candidato A.2 PRIVADO criado, com 20 arquivos e manifesto proprio.')
            print('CANDIDATO=' + str(dest))
            print('HISTORICO/CADASTROS: nao alterados.')
        else:
            need(args.candidato is not None, 'informe --candidato')
            fp = verify_historical_and_registries(project, private, snapshot, backup_old, plugin)
            target_root_ok(backup_new, project, private, create=False)
            old = historic_bytes(snapshot)
            verify_candidate(args.candidato.absolute(), fp, old)
            print('APROVADO: integridade e delta do candidato A.2 verificados (20 arquivos).')
            print('ATENCAO: candidato NAO e snapshot final, nem liberacao do preflight antigo.')
        print('DECISAO: NO-GO; 21 pendencias; CORTE 8883 NAO AUTORIZADO.')
        return 0
    except (Block, p2.Block, c.Block, c4.Block, c6.Block, c7.Block,
            OSError, ValueError, TypeError, KeyError, OverflowError):
        print('BLOQUEIO: fonte, vinculo, certificado ou candidato nao validado. '
              'Nenhum broker ou cadastro alterado. CORTE 8883 NAO AUTORIZADO.',
              file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
