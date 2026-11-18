#!/usr/bin/env python3
"""Fase 8.4.5.2: snapshot privado e configuracao CANDIDATA local, sem cutover.

NUNCA altera a configuracao, certificados ou usuarios dos brokers 8883/8884.
Todas as gravacoes sao restritas a ~/server_backups/fase8_4_5_2/.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import stat
import subprocess
import sys
import tempfile

import fase8_4_5_1_auditoria as base_audit

MAX_FILE = 8 * 1024 * 1024
MAX_MANIFEST = 64 * 1024
CANDIDATE_PORT = 8895  # NUNCA 8883
PLUGIN = Path('/usr/lib/mosquitto_dynamic_security.so')
NAME = 'phase8452-manifest.json'
SPECS: dict[str, tuple[str, bool]] = {
    'legacy/mosquitto.conf': ('root/mosquitto/mosquitto.conf', True),
    'legacy/passwords': ('root/mosquitto/passwords', True),
    'legacy/acl': ('root/mosquitto/acl', True),
    'legacy/devices.json': ('root/mosquitto/devices.json', True),
    'legacy/mqtt-bridge.token': ('root/mqtt-bridge.token', True),
    'legacy/mqtt-lab.token': ('root/mqtt-lab.token', True),
    'legacy/certs/ca.crt': ('project/certs/ca.crt', False),
    'legacy/certs/localhost.crt': ('project/certs/localhost.crt', False),
    'legacy/certs/localhost.key': ('project/certs/localhost.key', True),
    'lab/mosquitto-lab.conf': ('root/phase8-4-2-lab/mosquitto-lab.conf', True),
    'lab/dynamic-security.json': ('root/phase8-4-2-lab/dynamic-security.json', True),
    'lab/provisioned.json': ('root/phase8-4-2-lab/provisioned.json', True),
    'lab/fase8_4_4_state.json': ('root/phase8-4-2-lab/fase8_4_4_state.json', True),
    'lab/pki/ca.crt': ('root/phase8-4-2-lab/pki/ca.crt', True),
    'lab/pki/ca.key': ('root/phase8-4-2-lab/pki/ca.key', True),
    'lab/pki/server.crt': ('root/phase8-4-2-lab/pki/server.crt', True),
    'lab/pki/server.key': ('root/phase8-4-2-lab/pki/server.key', True),
    'lab/clients/device-sensor01.opts': ('root/phase8-4-2-lab/clients/device-sensor01.opts', True),
    'lab/clients/device-sensor02.opts': ('root/phase8-4-2-lab/clients/device-sensor02.opts', True),
    'lab/clients/lab84-bridge.opts': ('root/phase8-4-2-lab/clients/lab84-bridge.opts', True),
}

class Block(Exception):
    """No confidential data in exception messages."""


def check_regular(path: Path, *, private: bool, limit: int = MAX_FILE) -> bytes:
    """Safe bounded file read: no symlinks/hardlinks, owner/mode and fstat checks."""
    try:
        # check all ancestors below the user's home for symlinks; don't follow final link
        home = Path.home()
        if path.is_relative_to(home):
            for parent in (path.parent, *path.parent.parents):
                if parent == home.parent:
                    break
                if parent.is_symlink():
                    raise Block('caminho com symlink')
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_nlink != 1 or not (0 < before.st_size <= limit)
            or (private and before.st_mode & 0o077)):
            raise Block('tipo, dono, tamanho ou permissao invalida')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            actual = os.fstat(fd)
            if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns):
                raise Block('arquivo alterado durante leitura')
            with os.fdopen(fd, 'rb', closefd=False) as f:
                content = f.read(limit + 1)
            after = os.fstat(fd)
            if (actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                raise Block('arquivo mudou durante leitura')
            if len(content) != before.st_size or len(content) > limit:
                raise Block('leitura incompleta')
            return content
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        raise Block('arquivo ausente ou inseguro') from None


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def secure_dir(p: Path) -> None:
    try:
        s = p.lstat()
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.geteuid() or (s.st_mode & 0o077):
            raise Block('diretorio nao privado')
    except OSError:
        raise Block('diretorio ausente') from None


def backup_root_ok(dest: Path, project: Path, root: Path, home: Path, *, create=False) -> None:
    if (not dest.is_absolute() or not dest.is_relative_to(home) or dest == home
        or dest.is_relative_to(project) or project.is_relative_to(dest)
        or dest.is_relative_to(root) or root.is_relative_to(dest)):
        raise Block('destino fora do armazenamento privado dedicado')
    secure_dir(home) if home != Path.home() else None  # fixtures; home do usuário pode ser 0755
    current = home
    for part in dest.relative_to(home).parts:
        current = current / part
        if not current.exists() and not current.is_symlink():
            if not create:
                # Check every existing ancestor; do not create during preflight.
                break
            current.mkdir(mode=0o700)
        secure_dir(current)


def sources(project: Path, root: Path) -> dict[str, Path]:
    out = {}
    for label, (src, _) in SPECS.items():
        prefix, relative = src.split('/', 1)
        out[label] = (project if prefix == 'project' else root) / relative
    return out


def check_baseline(project: Path, root: Path, plugin: Path) -> None:
    # Phase 8.4.5.1 is the single source of truth for ACL, inventory and listeners.
    with redirect_stdout(io.StringIO()):
        status = base_audit.audit(project, root, plugin, runtime=False)
    if status != 0:
        raise Block('auditoria 8.4.5.1 nao aprovada; nenhuma escrita')
    # Pending state with incomplete step must block snapshot prep.
    pending = root / 'phase8-4-2-lab' / 'clients'
    if any(x.name.endswith('.pending') for x in pending.iterdir()):
        raise Block('rotacao pendente: inspecionar manualmente')


def gather(project: Path, root: Path) -> dict[str, bytes]:
    result = {}
    for label, source in sources(project, root).items():
        try:
            result[label] = check_regular(source, private=SPECS[label][1])
        except Block:
            raise Block(f'arquivo obrigatorio nao validado: {label}') from None
    # Ensure cross-file changes didn't occur while copying a live broker state.
    for label, source in sources(project, root).items():
        if sha(check_regular(source, private=SPECS[label][1])) != sha(result[label]):
            raise Block('arquivos de origem instaveis durante o snapshot')
    return result


def write_exclusive(path: Path, payload: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    try:
        with os.fdopen(fd, 'wb', closefd=False) as out:
            out.write(payload)
            out.flush()
            os.fsync(out.fileno())
    finally:
        os.close(fd)


def mkdirs_locked(top: Path, relative: PurePosixPath) -> Path:
    cur = top
    for segment in relative.parts:
        if segment in ('', '.', '..'):
            raise Block('caminho relativo inseguro')
        cur = cur / segment
        if not cur.exists() and not cur.is_symlink():
            cur.mkdir(mode=0o700)
        secure_dir(cur)
    return cur


def candidate_config(snapshot: Path, plugin: Path) -> bytes:
    """Quarantine simulation config. References COPIES only, never real broker paths."""
    candidate = snapshot / 'candidate'
    lines = [
        '# RUST-SERVER 8.4.5.2: CANDIDATA APENAS PARA SIMULACAO FUTURA',
        '# NAO E CONFIGURACAO DE PRODUCAO. PARIDADE NAO VALIDADA.',
        'persistence false',
        'log_dest stdout',
        'connection_messages true',
        'max_packet_size 8192',
        'max_inflight_messages 16',
        f'plugin_load dynsec8452 {plugin}',
        f'plugin_opt_config_file {candidate / "dynamic-security.json"}',
        f'listener {CANDIDATE_PORT} 127.0.0.1',
        'listener_allow_anonymous false',
        f'certfile {snapshot / "files/legacy/certs/localhost.crt"}',
        f'keyfile {snapshot / "files/legacy/certs/localhost.key"}',
        'tls_version tlsv1.2',
        'plugin_use dynsec8452',
        '',
    ]
    return ('\n'.join(lines)).encode('utf-8')


def verify_candidate(snapshot: Path, plugin: Path, *, configured_root: Path | None = None) -> None:
    conf = check_regular(snapshot / 'candidate/mosquitto-candidate.conf', private=True)
    expected = candidate_config(configured_root or snapshot, plugin)
    if conf != expected or b'listener 8883 ' in conf or b'listener 8884 ' in conf:
        raise Block('configuracao candidata alterada ou perigosa')
    dyn = check_regular(snapshot / 'candidate/dynamic-security.json', private=True)
    src = check_regular(snapshot / 'files/lab/dynamic-security.json', private=True)
    if dyn != src:
        raise Block('estado candidato nao confere com snapshot isolado')


def manifest_files(snapshot: Path) -> list[dict]:
    return [{'name': k, 'size': (snapshot/'files'/k).stat().st_size,
             'sha256': sha(check_regular(snapshot/'files'/k, private=True))}
            for k in sorted(SPECS)]


def verify(snapshot: Path, plugin: Path, *, configured_root: Path | None = None) -> int:
    secure_dir(snapshot)
    secure_dir(snapshot/'files')
    secure_dir(snapshot/'candidate')
    manifest_bytes = check_regular(snapshot / NAME, private=True, limit=MAX_MANIFEST)
    try:
        manifest = json.loads(manifest_bytes)
    except (ValueError, UnicodeError):
        raise Block('manifesto invalido') from None
    if (not isinstance(manifest, dict) or manifest.get('schema') != 1 or
        manifest.get('phase') != '8.4.5.2' or manifest.get('cutover_authorized') is not False or
        manifest.get('candidate_port') != CANDIDATE_PORT or
        not isinstance(manifest.get('files'), list) or len(manifest['files']) != len(SPECS)):
        raise Block('manifesto inesperado')
    if (not all(isinstance(e, dict) for e in manifest['files']) or
        {e.get('name') for e in manifest['files']} != set(SPECS)):
        raise Block('inventario de snapshot divergente')
    for entry in manifest['files']:
        label = entry['name']
        b = check_regular(snapshot / 'files' / label, private=True)
        if entry.get('size') != len(b) or entry.get('sha256') != sha(b):
            raise Block('SHA-256 divergente: integridade reprovada')
        # Every nested directory must be private and not a symlink.
        p = (snapshot / 'files' / label).parent
        while p != snapshot:
            secure_dir(p)
            p = p.parent
    verify_candidate(snapshot, plugin, configured_root=configured_root)
    return len(SPECS)


def preflight(project: Path, root: Path, plugin: Path, dest: Path, home: Path) -> None:
    if os.geteuid() == 0:
        raise Block('sudo/root proibido')
    backup_root_ok(dest, project, root, home, create=False)  # checar ancestrais existentes, mesmo sem destino
    if plugin.is_symlink() or not plugin.is_file():
        raise Block('plugin Dynamic Security nao encontrado')
    check_baseline(project, root, plugin)
    for label, source in sources(project, root).items():
        try:
            check_regular(source, private=SPECS[label][1])
        except Block:
            raise Block(f'arquivo requerido ausente/inseguro: {label}') from None


def prepare(project: Path, root: Path, plugin: Path, dest: Path, home: Path) -> Path:
    preflight(project, root, plugin, dest, home)
    contents = gather(project, root)
    backup_root_ok(dest, project, root, home, create=True)
    # An exclusive, private staging directory. Final rename only after verification.
    temp = Path(tempfile.mkdtemp(prefix='.incompleto-8452-', dir=dest))
    os.chmod(temp, 0o700)
    # Reserve final identity before writing candidate; atomic rename after checks.
    final = dest / ('snapshot-' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                    + '-' + secrets.token_hex(6))
    if final.exists() or final.is_symlink():
        raise Block('snapshot ja existente; nao sobrescrever')
    try:
        for label, payload in sorted(contents.items()):
            where = temp / 'files' / label
            mkdirs_locked(temp, PurePosixPath('files') / PurePosixPath(label).parent)
            write_exclusive(where, payload)
        mkdirs_locked(temp, PurePosixPath('candidate'))
        write_exclusive(temp / 'candidate/dynamic-security.json', contents['lab/dynamic-security.json'])
        write_exclusive(temp / 'candidate/mosquitto-candidate.conf', candidate_config(final, plugin))
        manifest = {
            'schema': 1, 'phase': '8.4.5.2', 'cutover_authorized': False,
            'candidate_port': CANDIDATE_PORT,
            'captured_at_utc': datetime.now(timezone.utc).isoformat(),
            'files': manifest_files(temp),
        }
        write_exclusive(temp / NAME, (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode())
        verify(temp, plugin, configured_root=final)
        os.rename(temp, final)
        verify(final, plugin)
        return final
    except Exception:
        # Leave incomplete (still 0700) data privately for investigation.
        # Never clean up or overwrite arbitrary paths while something failed.
        raise



def simulated_restore(snapshot: Path, plugin: Path) -> int:
    n = verify(snapshot, plugin)
    # Only an ephemeral restore under private storage; never writes to source brokers.
    with tempfile.TemporaryDirectory(prefix='.restauracao-simulada-8452-', dir=snapshot.parent) as location:
        scratch = Path(location)
        os.chmod(scratch, 0o700)
        for label in sorted(SPECS):
            target = scratch / label
            mkdirs_locked(scratch, PurePosixPath(label).parent)
            data = check_regular(snapshot/'files'/label, private=True)
            write_exclusive(target, data)
            if sha(check_regular(target, private=True)) != sha(data):
                raise Block('falha na simulacao de copia')
    return n


def cli() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=('preflight', 'preparar', 'verificar', 'simular-restauracao', 'validar-config'))
    p.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    p.add_argument('--private-root', type=Path, default=Path.home()/'.config/rust-server')
    p.add_argument('--backups-root', type=Path, default=Path.home()/'server_backups/fase8_4_5_2')
    p.add_argument('--plugin-path', type=Path, default=PLUGIN)
    p.add_argument('--snapshot', type=Path)
    args = p.parse_args()
    project, root, plugin, dest = (x.absolute() for x in (
        args.project_root, args.private_root, args.plugin_path, args.backups_root))
    try:
        if args.action in ('preflight', 'preparar'):
            preflight(project, root, plugin, dest, Path.home())
            if args.action == 'preflight':
                print('APROVADO: 8.4.5.1 e arquivos obrigatorios verificados. Nenhuma escrita realizada.')
                print('Corte para 8883: NAO AUTORIZADO.')
            else:
                folder = prepare(project, root, plugin, dest, Path.home())
                print('APROVADO: snapshot privado criado e verificado (' + str(len(SPECS)) + ' arquivos).')
                print('SNAPSHOT=' + str(folder))
                print('CANDIDATO: somente listener 127.0.0.1:8895; NAO executar broker nesta subfase.')
                print('Nao importar identidade lab como identidade de producao; paridade pendente 8.4.5.4.')
        else:
            if args.snapshot is None:
                raise Block('informe --snapshot com o caminho exato retornado no preparar')
            snap = args.snapshot.absolute()
            backup_root_ok(dest, project, root, Path.home(), create=False)
            if snap.parent != dest or not snap.name.startswith('snapshot-') or snap.is_symlink():
                raise Block('snapshot fora do local esperado')
            if args.action == 'simular-restauracao':
                n = simulated_restore(snap, plugin)
                print(f'APROVADO: restauracao de arquivos em diretorio temporario ({n} arquivos); broker intacto.')
                print('ISSO NAO COMPROVA ROLLBACK OPERACIONAL: fase 8.4.5.3.')
            else:
                n = verify(snap, plugin)
                if args.action == 'validar-config':
                    # Mosquitto 2.1+ --test-config does not start or bind any listener.
                    check = subprocess.run(['mosquitto', '--test-config', '-c',
                              str(snap/'candidate/mosquitto-candidate.conf')],
                              capture_output=True, timeout=15, check=False)
                    if check.returncode:
                        raise Block('mosquitto --test-config reprovado; saida bruta omitida')
                    verify(snap, plugin)  # Detect any plugin-side unexpected changes.
                    print('APROVADO: mosquitto --test-config (sem iniciar o broker).')
                print(f'APROVADO: SHA-256, permissoes, manifesto e candidato verificados ({n} arquivos).')
                print('8883 nao foi alterado. Corte NAO AUTORIZADO.')
        return 0
    except Block as exc:
        # Block messages are hardcoded security classifications; no file contents or secrets.
        print(f'BLOQUEIO: {exc}. Nenhum broker foi alterado.', file=sys.stderr)
        return 2
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired):
        # Raw OS and library errors may contain private paths/data; do not print them.
        print('BLOQUEIO: falha de sistema/arquivo; nao expor detalhes privados.', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(cli())
