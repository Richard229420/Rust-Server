#!/usr/bin/env python3
"""C.10 — registros versionados do baseline C.9, sem migracao de aprovacoes.

Camada independente de acompanhamento: NAO substitui schemas nem aprovacoes
originais C.4/C.6/C.7/C.8. Exige testemunho C.9 valido em cada operacao.
Nao inicia MQTT, executa Git, altera broker ou reativa dispositivo revogado.
"""
from __future__ import annotations
import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import fase8_4_5_4c9_reconciliacao_baseline as c9
import fase8_4_5_4c8_evidencias_cv1 as c8

VERSIONS_ROOT = Path.home() / '.config/rust-server/phase8-4-5-4c/versions'
SCHEMA = 'rust-server/phase8.4.5.4-c10/versioned-pending-v1'
HEX = re.compile(r'^[0-9a-f]{64}$')
REF = re.compile(r'^EV-A-[A-Z0-9]{6,32}$')
DOCS = ('c4-planejamento.json', 'c6-indice-vazio.json', 'c7-coleta-pendente.json', 'c8-pendencias.json')
EVIDENCE = 'registro-evidencias-c10.json'
MANIFEST = 'manifesto-c10.json'

class Block(Exception):
    pass

def ensure(ok, reason):
    if not ok: raise Block(reason)

def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()

def encode(obj: dict) -> bytes:
    return (json.dumps(obj, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()

def utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')

def private_directory(path: Path) -> None:
    ensure(not path.is_symlink(), 'diretorio privado nao pode ser symlink')
    try: info = path.stat()
    except OSError: raise Block('diretorio privado ausente') from None
    ensure(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
           and stat.S_IMODE(info.st_mode) == 0o700,
           'diretorio privado deve ser do usuario e 0700')

def private_read(path: Path, *, limit=2_000_000) -> bytes:
    ensure(not path.is_symlink(), 'arquivo symlink recusado')
    try: info = path.stat()
    except OSError: raise Block('arquivo privado ausente') from None
    ensure(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
           and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
           and 0 < info.st_size <= limit, 'arquivo privado deve ser 0600 e regular')
    return path.read_bytes()

def read_json(path: Path) -> dict:
    try: obj = json.loads(private_read(path))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise Block('JSON privado malformado') from None
    ensure(isinstance(obj, dict), 'JSON privado nao e objeto')
    return obj

def exclusive(path: Path, raw: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os,'O_NOFOLLOW',0), 0o600)
    with os.fdopen(fd, 'wb') as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())

def atomic_rewrite(path: Path, raw: bytes) -> None:
    private_read(path)
    fd, temp = tempfile.mkstemp(prefix='.c10-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(raw); f.flush(); os.fsync(f.fileno())
        os.replace(temp, path)
        syncfd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(syncfd)
        finally: os.close(syncfd)
    finally:
        if os.path.exists(temp): os.unlink(temp)

def requirements() -> list[dict]:
    lines = [{'id': i, 'category': category, 'description': desc,
              'required_evidence': guidance, 'decision': 'PENDING_INDEPENDENT_REVIEW'}
             for i, category, desc, guidance in c8.REQUIREMENTS]
    ensure(len(lines) == 21 and len({r['id'] for r in lines}) == 21,
           '21 requisitos C-V1 nao conferem')
    ensure({r['category'] for r in lines} == {'lab','bridge','device-sensor02','operacionais'}
           and all('sensor01' not in r['id'] for r in lines),
           'identidades inesperadas no cadastro')
    return lines

def gate() -> dict:
    """C.9 reexecuta verificacoes C.2/C.3, PKI staging e indices historicos."""
    args = c9.parser().parse_args(['verificar'])
    ensure(args.state == c9.STATE_DEFAULT, 'testemunho C9 fora do caminho esperado')
    result = c9.audit(args)
    witness_raw = c9.private_file(args.state)
    try: witness = json.loads(witness_raw)
    except (ValueError, UnicodeDecodeError): raise Block('testemunho C9 malformado') from None
    c9.validate_record(witness, args, result)
    ensure(witness['approval'] == 'NOT_GRANTED' and witness['cutover_8883'] == 'FORBIDDEN'
           and witness['c_v1_pending'] == 21 and witness['evidence_count_migrated'] == 0,
           'gates do C9 nao conferem')
    return {'old': result['historic_manifest_sha256'],
            'new': result['current_manifest_sha256'],
            'c9_sha256': digest(witness_raw)}

def expected_documents(link: dict, created: str) -> dict[str, dict]:
    common = dict(schema=SCHEMA, scenario='A', current_manifest_sha256=link['new'],
                  created_utc=created, approval='NOT_GRANTED', cutover_8883='FORBIDDEN')
    return {
        DOCS[0]: {**common, 'component': 'C4', 'revalidation': 'PENDING',
                  'source': 'DECLARATIONS_HISTORICAL_NOT_TRANSFERRED',
                  'identities': [{'identity': name, 'runtime': 'NOT_CONFIRMED',
                                  'review': 'pending-independent-review'}
                                 for name in ('lab', 'bridge', 'device-sensor02')]},
        DOCS[1]: {**common, 'component': 'C6', 'revalidation': 'PENDING',
                  'references': [], 'historical_evidence_transferred': 0},
        DOCS[2]: {**common, 'component': 'C7', 'revalidation': 'PENDING',
                  'collection': 'NOT_PERFORMED', 'scenario_b_is_not_proof': True},
        DOCS[3]: {**common, 'component': 'C8', 'revalidation': 'PENDING',
                  'requirements': requirements(), 'pending_count': 21},
    }

def empty_evidence(link: dict) -> dict:
    return {'schema': SCHEMA, 'component': 'C10-EVIDENCE', 'scenario': 'A',
            'current_manifest_sha256': link['new'], 'entries': [],
            'approval': 'NOT_GRANTED', 'cutover_8883': 'FORBIDDEN'}

def validate_evidence(data: dict, link: dict) -> None:
    expected = empty_evidence(link)
    ensure(isinstance(data, dict) and set(data) == set(expected)
           and all(data[k] == expected[k] for k in expected if k != 'entries'),
           'indice de evidencias C10 malformado ou permissivo')
    entries = data['entries']
    ensure(isinstance(entries, list) and len(entries) <= 210, 'registro de evidencias invalido')
    valid = {x['id'] for x in requirements()}
    seen = set(); by_ref = {}
    for e in entries:
        ensure(isinstance(e, dict) and set(e) == {'item_id','reference','sha256','kind','registered_utc','review'},
               'campos de evidencia inesperados')
        ensure(e['item_id'] in valid and isinstance(e['reference'], str)
               and REF.fullmatch(e['reference']) and isinstance(e['sha256'], str)
               and HEX.fullmatch(e['sha256']) and e['kind'] in c8.KINDS
               and e['review'] == 'pending-independent-review'
               and isinstance(e['registered_utc'], str) and e['registered_utc'].endswith('+00:00'),
               'evidencia fora da politica C10')
        pair = (e['item_id'], e['reference'])
        ensure(pair not in seen, 'referencia duplicada no mesmo requisito')
        seen.add(pair)
        if e['reference'] in by_ref:
            ensure(by_ref[e['reference']] == e['sha256'], 'mesma referencia com hash diferente')
        by_ref[e['reference']] = e['sha256']

def version_path(link: dict, root: Path = VERSIONS_ROOT) -> Path:
    ensure(HEX.fullmatch(link['new']) is not None, 'hash da linha de base invalido')
    return root / link['new']

def initialize(link: dict, root: Path = VERSIONS_ROOT) -> Path:
    private_directory(root.parent)
    if not root.exists(): root.mkdir(mode=0o700)
    private_directory(root)
    dest = version_path(link, root)
    ensure(not dest.exists() and not dest.is_symlink(),
           'versao C10 ja existe; jamais sobrescrever')
    dest.mkdir(mode=0o700)
    created = utc()
    docs = expected_documents(link, created)
    serialized = {name: encode(obj) for name, obj in docs.items()}
    manifest = {'schema': SCHEMA, 'created_utc': created,
                'historic_manifest_sha256': link['old'],
                'current_manifest_sha256': link['new'],
                'c9_witness_sha256': link['c9_sha256'],
                'document_sha256': {name: digest(data) for name, data in serialized.items()},
                'evidence_count_migrated': 0, 'c_v1_pending': 21,
                'approval': 'NOT_GRANTED', 'cutover_8883': 'FORBIDDEN'}
    for name in DOCS: exclusive(dest / name, serialized[name])
    exclusive(dest / EVIDENCE, encode(empty_evidence(link)))
    exclusive(dest / MANIFEST, encode(manifest))  # ultimo: ausencia significa escrita incompleta
    return dest

def verify_bundle(link: dict, root: Path = VERSIONS_ROOT) -> tuple[Path, dict]:
    private_directory(root.parent)
    private_directory(root)
    dest = version_path(link, root)
    private_directory(dest)
    manifest = read_json(dest / MANIFEST)
    ensure(set(manifest) == {'schema','created_utc','historic_manifest_sha256',
                             'current_manifest_sha256','c9_witness_sha256','document_sha256',
                             'evidence_count_migrated','c_v1_pending','approval','cutover_8883'},
           'manifesto C10 com campos inesperados')
    ensure(manifest['schema'] == SCHEMA and manifest['historic_manifest_sha256'] == link['old']
           and manifest['current_manifest_sha256'] == link['new']
           and manifest['c9_witness_sha256'] == link['c9_sha256']
           and manifest['evidence_count_migrated'] == 0 and manifest['c_v1_pending'] == 21
           and manifest['approval'] == 'NOT_GRANTED' and manifest['cutover_8883'] == 'FORBIDDEN',
           'manifesto C10 nao vinculado ao C9')
    ensure(isinstance(manifest['created_utc'],str) and manifest['created_utc'].endswith('+00:00'),
           'timestamp do manifesto invalido')
    docs = expected_documents(link, manifest['created_utc'])
    ensure(set(manifest['document_sha256']) == set(DOCS), 'inventario C10 inesperado')
    for name, expected in docs.items():
        content = private_read(dest / name)
        ensure(digest(content) == manifest['document_sha256'][name]
               and content == encode(expected), f'plano C10 divergente: {name}')
    evidence = read_json(dest / EVIDENCE)
    validate_evidence(evidence, link)
    return dest, evidence

def append_entry(link: dict, item: str, ref: str, h: str, kind: str, root: Path = VERSIONS_ROOT) -> int:
    dest, _ = verify_bundle(link, root)
    ensure(item in {r['id'] for r in requirements()}, 'requisito desconhecido')
    ensure(bool(REF.fullmatch(ref)) and bool(HEX.fullmatch(h)) and kind in c8.KINDS,
           'usar referencia opaca EV-A-..., SHA256 e tipo permitido')
    lockpath = dest / '.c10.lock'
    fd = os.open(lockpath, os.O_CREAT | os.O_RDWR | getattr(os,'O_NOFOLLOW',0), 0o600)
    try:
        s = os.fstat(fd)
        ensure(stat.S_ISREG(s.st_mode) and s.st_uid == os.getuid() and
               stat.S_IMODE(s.st_mode) == 0o600 and s.st_nlink == 1, 'lock inseguro')
        fcntl.flock(fd, fcntl.LOCK_EX)
        _, data = verify_bundle(link, root)  # revalidar sob lock
        data['entries'].append({'item_id': item, 'reference': ref, 'sha256': h,
                                'kind': kind, 'registered_utc': utc(),
                                'review': 'pending-independent-review'})
        validate_evidence(data, link)
        atomic_rewrite(dest / EVIDENCE, encode(data))
        return len(data['entries'])
    finally:
        os.close(fd)

def cli(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    sub = p.add_subparsers(dest='action', required=True)
    for cmd in ('preflight','iniciar','verificar','status','roteiro'):
        sub.add_parser(cmd)
    reg = sub.add_parser('registrar', help='referenciar documento redigido do cenario A')
    reg.add_argument('--item', required=True, choices=[i[0] for i in c8.REQUIREMENTS])
    reg.add_argument('--referencia', required=True)
    reg.add_argument('--sha256', required=True)
    reg.add_argument('--tipo', required=True, choices=c8.KINDS)
    args = p.parse_args(argv)
    try:
        if args.action == 'roteiro':
            for item in requirements():
                print(f"{item['id']} ({item['category']}): {item['required_evidence']}")
            print('21 pendencias sem baixa; corte 8883 nao autorizado.')
            return 0
        link = gate()
        if args.action == 'preflight':
            print('APROVADO: testemunho C9, baselines e vinculos historicos validados.')
            print('C10 ainda nao inicializada; nenhuma evidencia transferida.')
            return 0
        if args.action == 'iniciar':
            initialize(link)
            print('APROVADO: nova versao documental C10 criada (0700/0600), sem alterar registros historicos.')
        dest, evidence = verify_bundle(link)
        if args.action in ('iniciar','verificar'):
            print('APROVADO: integridade C10 e testemunho C9 conferidos.')
        elif args.action == 'registrar':
            count = append_entry(link, args.item, args.referencia, args.sha256, args.tipo)
            print(f'APROVADO: metadado de {args.item} registrado; {count} referencia(s); revisao independente pendente.')
            _, evidence = verify_bundle(link)
        covered = {e['item_id'] for e in evidence['entries']}
        print(f"C10: {len(evidence['entries'])} referencias opacas; {len(covered)}/21 com metadados; 21/21 PENDENCIAS ABERTAS.")
        print('C4/C6/C7/C8 NOVOS: registros de planejamento, NAO revalidacoes operacionais.')
        print('GATES: Seguranca, Git/CI, operacao e janela pendentes; corte 8883 NAO AUTORIZADO.')
        return 0
    except (Block, c9.Block, OSError, ValueError, TypeError) as error:
        # Algumas falhas de bibliotecas podem carregar caminhos; nao publicar excecao original.
        msg = str(error) if type(error) is Block else type(error).__name__
        print(f'BLOQUEADO: {msg}. Nenhuma autorizacao de corte.', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(cli())
