#!/usr/bin/env python3
"""Fase 8.4.1: inventario e snapshots privados do estado MQTT da Fase 8.3.

Nao modifica o broker, suas credenciais ou a instalacao em producao.
Somente Python stdlib, executar como usuario nao privilegiado no Arch Linux.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile

MAX_BYTES = 8 * 1024 * 1024
PLUGIN = Path('/usr/lib/mosquitto_dynamic_security.so')
TOKEN_ID = re.compile(r'[a-z][a-z0-9-]{2,31}\.token\Z')
EXPECTED = ('mosquitto/mosquitto.conf', 'mosquitto/passwords',
            'mosquitto/acl', 'mosquitto/devices.json',
            'credentials/mqtt-bridge.token', 'credentials/mqtt-lab.token',
            'certs/ca.crt', 'certs/localhost.crt', 'certs/localhost.key')

class Abort(Exception):
    pass


def private_dir(path: Path, *, create: bool = False) -> None:
    if create:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise Abort(f'Diretorio ausente/inseguro: {path}')
    info = path.stat()
    if info.st_uid != os.geteuid() or (info.st_mode & 0o077):
        raise Abort(f'Diretorio deve pertencer ao usuario atual e ter modo 0700: {path}')


def checked_file(path: Path, *, private: bool = True) -> bytes:
    # Nao atravessar diretorios simbolicos ao restaurar um snapshot.
    if any(parent.is_symlink() for parent in path.parents):
        raise Abort(f'Diretorio pai e link simbolico: {path}')
    if path.is_symlink() or not path.is_file():
        raise Abort(f'Arquivo ausente ou symlink: {path}')
    s = path.stat()
    if s.st_uid != os.geteuid() or s.st_nlink != 1 or s.st_size > MAX_BYTES:
        raise Abort(f'Proprietario, hardlink ou tamanho inseguro: {path}')
    if private and (s.st_mode & 0o077):
        raise Abort(f'Arquivo privado permite acesso a outros usuarios (esperado 0600): {path}')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (s.st_dev, s.st_ino, s.st_size):
            raise Abort(f'Arquivo alterado durante leitura: {path}')
        if opened.st_uid != os.geteuid() or opened.st_nlink != 1 or (private and (opened.st_mode & 0o077)):
            raise Abort(f'Permissoes ou links alterados durante leitura: {path}')
        with os.fdopen(fd, 'rb', closefd=False) as fh:
            data = fh.read(MAX_BYTES + 1)
        if len(data) != s.st_size:
            raise Abort(f'Arquivo instavel ou excedeu limite: {path}')
        return data
    finally:
        os.close(fd)


def paths(project: Path, root: Path) -> dict[str, tuple[Path, bool]]:
    broker = root / 'mosquitto'
    tokens = root / 'device-tokens'
    private_dir(root)
    private_dir(broker)
    if tokens.exists() or tokens.is_symlink():
        private_dir(tokens)
    certs = project / 'certs'
    if certs.is_symlink() or not certs.is_dir():
        raise Abort('Diretorio certs/ do projeto ausente ou symlink')
    # Certificados publicos nao exigem 0600; chaves, senhas, estado e tokens exigem.
    data = {
        'mosquitto/mosquitto.conf': (broker / 'mosquitto.conf', True),
        'mosquitto/passwords': (broker / 'passwords', True),
        'mosquitto/acl': (broker / 'acl', True),
        'mosquitto/devices.json': (broker / 'devices.json', True),
        'credentials/mqtt-bridge.token': (root / 'mqtt-bridge.token', True),
        'credentials/mqtt-lab.token': (root / 'mqtt-lab.token', True),
        'certs/ca.crt': (certs / 'ca.crt', False),
        'certs/localhost.crt': (certs / 'localhost.crt', False),
        'certs/localhost.key': (certs / 'localhost.key', True),
    }
    for extra in ('ca.key', 'ca.pem'):
        p = certs / extra
        if p.exists() or p.is_symlink():
            data[f'certs/{extra}'] = (p, True)
    if tokens.is_dir():
        for p in sorted(tokens.iterdir()):
            if not TOKEN_ID.fullmatch(p.name):
                raise Abort(f'Nome inesperado no diretorio de tokens: {p.name}')
            data[f'credentials/device-tokens/{p.name}'] = (p, True)
    return data


def source_bytes(project: Path, root: Path) -> tuple[dict[str, bytes], dict]:
    p = paths(project, root)
    contents = {rel: checked_file(location, private=is_private)
                for rel, (location, is_private) in sorted(p.items())}
    conf = contents['mosquitto/mosquitto.conf'].decode('utf-8')
    for required in (
        'listener 8883 127.0.0.1', 'allow_anonymous false',
        f'password_file {root / "mosquitto/passwords"}',
        f'acl_file {root / "mosquitto/acl"}',
        f'certfile {project / "certs/localhost.crt"}',
        f'keyfile {project / "certs/localhost.key"}',
    ):
        if required not in [ln.strip() for ln in conf.splitlines()]:
            raise Abort(f'Broker configurado diferentemente da Fase 8.3: diretiva {required.split()[0]}')
    if re.search(r'^\s*(?:plugin|global_plugin|plugin_load|plugin_use)\s', conf, re.M):
        raise Abort('Broker atual ja usa plugin: revisar configuracao antes do snapshot')
    try:
        inventory = json.loads(contents['mosquitto/devices.json'])
        states = inventory['devices']
        if not isinstance(states, dict) or any(
            not isinstance(v, dict) or v.get('state') not in ('active', 'revoked')
            for v in states.values()
        ):
            raise ValueError('inventario invalido')
    except (ValueError, KeyError, TypeError) as exc:
        raise Abort('devices.json ausente de estrutura valida') from exc
    meta = {'devices': {k: v['state'] for k, v in sorted(states.items())},
            'files': len(contents), 'tokens_temporarios': sum(x.startswith('credentials/device-tokens/') for x in contents)}
    return contents, meta


def module_info(plugin: Path) -> bool:
    if plugin.is_symlink():
        return False
    return plugin.is_file() and os.access(plugin, os.R_OK)


def inventory(project: Path, root: Path, plugin: Path) -> int:
    contents, meta = source_bytes(project, root)
    print('=== FASE 8.4.1: INVENTARIO (sem segredos) ===')
    print('Pacote Mosquitto:', end=' ')
    try:
        result = subprocess.run(['pacman', '-Q', 'mosquitto'], capture_output=True, text=True, check=False)
        print(result.stdout.strip() if result.returncode == 0 else 'nao confirmado')
    except FileNotFoundError:
        print('pacman indisponivel neste ambiente')
    print(f'Plugin Dynamic Security: {"PRESENTE" if module_info(plugin) else "AUSENTE"} ({plugin})')
    print('Broker atual: configuracao legada TLS/ACL, nenhuma alteracao aplicada')
    print(f'Arquivos elegiveis ao snapshot: {len(contents)}')
    print(f'Tokens temporarios de dispositivo presentes: {meta["tokens_temporarios"]}')
    for device, state in meta['devices'].items():
        print(f'Dispositivo: {device} -> {state}')
    return 0 if module_info(plugin) else 2


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def private_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.parent.chmod(0o700)
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


def backup(project: Path, root: Path, backups: Path, plugin: Path) -> Path:
    if backups.is_relative_to(project) or backups.is_relative_to(root):
        raise Abort('O destino do backup deve ficar fora do codigo e da pasta de credenciais')
    contents, meta = source_bytes(project, root)
    private_dir(backups, create=True)
    tmp = Path(tempfile.mkdtemp(prefix='.parcial-fase841-', dir=backups))
    try:
        os.chmod(tmp, 0o700)
        records = []
        for rel, data in sorted(contents.items()):
            private_write(tmp / 'payload' / rel, data)
            records.append({'path': rel, 'bytes': len(data), 'sha256': digest(data)})
        # Verifica se houve mudanca durante a coleta, inclusive arquivos adicionados/removidos.
        after, _ = source_bytes(project, root)
        if {k: digest(v) for k, v in contents.items()} != {k: digest(v) for k, v in after.items()}:
            raise Abort('Arquivos de origem mudaram durante o backup; refaca sem alterar dispositivos')
        manifest = {
            'format': 'rust-server-fase8-4-1-v1',
            'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
            'source_project': str(project),
            'source_private_root': str(root),
            'plugin_present': module_info(plugin),
            'devices': meta['devices'],
            'files': records,
            'remark': 'SNAPSHOT PRIVADO. Inclui credenciais/chaves; nao publicar no Git nem enviar ao chat.',
        }
        private_write(tmp / 'manifest.json', (json.dumps(manifest, indent=2, ensure_ascii=False) + '\n').encode())
        final = backups / (dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + secrets.token_hex(4))
        tmp.rename(final)
        return final
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def find_latest(backups: Path) -> Path:
    private_dir(backups)
    folders = [p for p in backups.iterdir() if p.is_dir() and not p.is_symlink() and not p.name.startswith('.')]
    if not folders:
        raise Abort('Nenhum snapshot disponivel')
    return sorted(folders)[-1]


def verify(snapshot: Path) -> list[tuple[str, bytes]]:
    private_dir(snapshot)
    try:
        manifest = json.loads(checked_file(snapshot / 'manifest.json'))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise Abort('Manifesto invalido') from exc
    if manifest.get('format') != 'rust-server-fase8-4-1-v1':
        raise Abort('Formato de snapshot desconhecido')
    records = manifest.get('files')
    if not isinstance(records, list) or len(records) < len(EXPECTED):
        raise Abort('Manifesto de arquivos incompleto')
    allowed_base = set(EXPECTED) | {'certs/ca.key', 'certs/ca.pem'}
    seen = set()
    result = []
    for record in records:
        if not isinstance(record, dict):
            raise Abort('Registro malformado')
        rel = record.get('path')
        if not isinstance(rel, str) or (rel not in allowed_base and not (
            rel.startswith('credentials/device-tokens/') and TOKEN_ID.fullmatch(rel.rsplit('/', 1)[-1])
            and rel.count('/') == 2
        )) or rel in seen:
            raise Abort('Caminho inesperado/duplicado no manifesto')
        seen.add(rel)
        data = checked_file(snapshot / 'payload' / rel)
        if len(data) != record.get('bytes') or digest(data) != record.get('sha256'):
            raise Abort(f'Integridade do snapshot nao confere: {rel}')
        result.append((rel, data))
    if not set(EXPECTED).issubset(seen):
        raise Abort('Arquivos obrigatorios ausentes do manifesto')
    # Detectar arquivos adicionais fora do manifesto, inclusive symlinks.
    payload = snapshot / 'payload'
    for entry in payload.rglob('*'):
        if entry.is_symlink():
            raise Abort('Snapshot contem symlink nao permitido')
        if entry.is_file() and str(entry.relative_to(payload)) not in seen:
            raise Abort('Snapshot contem arquivo nao registrado')
    return result


def simulate(snapshot: Path, backups: Path) -> None:
    validated = verify(snapshot)
    private_dir(backups)
    tmp = Path(tempfile.mkdtemp(prefix='.restauracao-simulada-', dir=backups))
    try:
        tmp.chmod(0o700)
        for rel, data in validated:
            private_write(tmp / rel, data)
        for rel, data in validated:
            if checked_file(tmp / rel) != data:
                raise Abort(f'Restauracao de teste falhou: {rel}')
    finally:
        shutil.rmtree(tmp)
    print(f'APROVADO: restauracao simulada de {len(validated)} arquivos, sem tocar no broker real.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('acao', choices=('inventario', 'backup', 'verificar', 'simular-restauracao'))
    parser.add_argument('--project', type=Path, default=Path.home() / 'server/services/multiprotocol')
    parser.add_argument('--root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--backups', type=Path, default=Path.home() / 'server_backups/fase8_4_1')
    parser.add_argument('--plugin', type=Path, default=PLUGIN)
    parser.add_argument('--snapshot', type=Path, help='Snapshot especifico; omitir para usar o mais recente')
    args = parser.parse_args()
    if os.geteuid() == 0:
        raise Abort('Nao executar como root/sudo')
    project = args.project.expanduser().absolute()
    root = args.root.expanduser().absolute()
    backups = args.backups.expanduser().absolute()
    if args.acao == 'inventario':
        return inventory(project, root, args.plugin)
    if args.acao == 'backup':
        out = backup(project, root, backups, args.plugin)
        n = len(verify(out))
        print(f'APROVADO: snapshot privado verificado ({n} arquivos).')
        print(f'SNAPSHOT={out}')
        return 0
    snap = args.snapshot.expanduser().absolute() if args.snapshot else find_latest(backups)
    if args.acao == 'verificar':
        files = verify(snap)
        print(f'APROVADO: integridade verificada ({len(files)} arquivos) em {snap}')
    else:
        simulate(snap, backups)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (Abort, OSError, KeyError) as exc:
        print(f'ERRO FASE 8.4.1: {exc}', file=sys.stderr)
        sys.exit(1)
