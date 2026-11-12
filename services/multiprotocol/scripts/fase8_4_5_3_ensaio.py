#!/usr/bin/env python3
"""Fase 8.4.5.3: ensaio isolado de candidato DynSec e rollback legado.

SO replica o snapshot 8.4.5.2 em scratch privado; 8895 DynSec e 8896 legado.
NUNCA inicia em 8883/8884; nao altera repositorio, brokers ou snapshot.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time

import fase8_4_5_2_preparar as phase2

CANDIDATE = 8895
ROLLBACK = 8896
HOST = '127.0.0.1'
TIMEOUT = 9


class Block(Exception):
    """Public messages never incorporate untrusted data or credentials."""


def require(cond: bool, reason: str) -> None:
    if not cond:
        raise Block(reason)


def private_write(path: Path, data: bytes) -> None:
    phase2.write_exclusive(path, data)


def available(port: int) -> bool:
    """Try binding the exact loopback address; never kills external processes."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((HOST, port))
            return True
        except OSError:
            return False


def port_alive(port: int) -> bool:
    try:
        with socket.create_connection((HOST, port), timeout=0.2):
            return True
    except OSError:
        return False


def probe_original() -> tuple[str, str]:
    # Port listing is passive and has no impact on the brokers.
    try:
        proc = subprocess.run(['ss', '-H', '-lnt'], stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=4, check=False, text=True)
        require(proc.returncode == 0, 'consulta passiva de listeners indisponivel')
        outputs = []
        for port in (8883, 8884):
            addresses = [line.split()[3] for line in proc.stdout.splitlines()
                         if len(line.split()) >= 4 and line.split()[3].endswith(f':{port}')]
            require(not addresses or addresses == [f'{HOST}:{port}'],
                    'listener original exposto ou inesperado')
            outputs.append('loopback' if addresses else 'parado')
        return tuple(outputs)  # type: ignore[return-value]
    except (OSError, subprocess.TimeoutExpired):
        raise Block('consulta passiva de listeners indisponivel') from None


def paths_ok(snapshot: Path, backups: Path, project: Path, private: Path) -> None:
    require(os.geteuid() != 0, 'nao executar como sudo/root')
    phase2.backup_root_ok(backups, project, private, Path.home(), create=False)
    require(snapshot.is_absolute() and snapshot.parent == backups and
            snapshot.name.startswith('snapshot-') and not snapshot.is_symlink(),
            'snapshot fora do diretorio permitido')


def assert_origins_match(snapshot: Path, project: Path, private: Path) -> None:
    """Block stale restore plans and detect outside edits while the rehearsal runs."""
    for label, origin in phase2.sources(project, private).items():
        live = phase2.check_regular(origin, private=phase2.SPECS[label][1])
        copy = phase2.check_regular(snapshot / 'files' / label, private=True)
        require(phase2.sha(live) == phase2.sha(copy),
                'snapshot desatualizado: origem diverge; reavaliar 8.4.5.2')


def prereq(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path) -> None:
    paths_ok(snapshot, backups, project, private)
    phase2.verify(snapshot, plugin)
    assert_origins_match(snapshot, project, private)
    require(not plugin.is_symlink() and plugin.is_file(), 'plugin DynSec ausente ou inseguro')
    for binary in ('mosquitto', 'mosquitto_pub', 'mosquitto_sub'):
        require(shutil.which(binary) is not None, 'ferramenta Mosquitto nao instalada')
    require(available(CANDIDATE) and available(ROLLBACK),
            'porta de ensaio 8895 ou 8896 ja ocupada')
    probe_original()


def restore_files(snapshot: Path, scratch: Path) -> None:
    """Exactly the 20 verified files; no hardlinks/symlinks to the source."""
    for label in phase2.SPECS:
        payload = phase2.check_regular(snapshot / 'files' / label, private=True)
        phase2.mkdirs_locked(scratch, PurePosixPath('files') / PurePosixPath(label).parent)
        target = scratch / 'files' / label
        private_write(target, payload)
        require(phase2.sha(phase2.check_regular(target, private=True)) == phase2.sha(payload),
                'arquivo nao recuperado corretamente')


def build_candidate(snapshot: Path, scratch: Path, plugin: Path) -> Path:
    phase2.mkdirs_locked(scratch, PurePosixPath('candidate'))
    payload = phase2.check_regular(scratch / 'files/lab/dynamic-security.json', private=True)
    private_write(scratch / 'candidate/dynamic-security.json', payload)
    config = scratch / 'candidate/mosquitto-candidate.conf'
    private_write(config, phase2.candidate_config(scratch, plugin))
    phase2.verify_candidate(scratch, plugin)
    require(b'listener 8895 127.0.0.1' in phase2.check_regular(config, private=True),
            'listener candidato nao restrito')
    return config


def build_rollback(scratch: Path) -> Path:
    """Whitelisted legacy config from snapshot copies, never real paths."""
    p = scratch / 'files/legacy'
    config = scratch / 'rollback/mosquitto-rollback.conf'
    phase2.mkdirs_locked(scratch, PurePosixPath('rollback'))
    content = '\n'.join((
        '# 8.4.5.3: ENSAIO LEGADO ISOLADO, SEM CUTOVER',
        'persistence false',
        'log_dest stderr',
        'max_packet_size 8192',
        'message_size_limit 2048',
        'max_queued_messages 64',
        'max_queued_bytes 65536',
        'max_connections 64',
        f'listener {ROLLBACK} {HOST}',
        'allow_anonymous false',
        f'password_file {p / "passwords"}',
        f'acl_file {p / "acl"}',
        f'certfile {p / "certs/localhost.crt"}',
        f'keyfile {p / "certs/localhost.key"}',
        'tls_version tlsv1.2',
        '',
    ))
    require('8883' not in content and '8884' not in content, 'rollback com porta de producao')
    private_write(config, content.encode('utf-8'))
    return config


def parse_lab_options(scratch: Path, user: str, port: int) -> bytes:
    """Rejects option injection and remaps only port and CA to scratch."""
    expected = {'device-sensor01': 'lab84-sensor01', 'device-sensor02': 'lab84-sensor02',
                'lab84-bridge': 'lab84-bridge'}
    require(user in expected, 'usuario nao previsto para ensaio')
    src = phase2.check_regular(scratch / f'files/lab/clients/{user}.opts', private=True)
    try:
        lines = src.decode('utf-8').splitlines()
        d = {}
        for line in lines:
            key, value = line.split(' ', 1)
            require(key not in d, 'opcao duplicada')
            d[key] = value
        require(tuple(d) == ('-h', '-p', '--cafile', '-u', '-P', '-i'), 'opts inesperadas')
        require(d['-h'] == 'localhost' and d['-p'] == '8884' and
                d['-u'] == user and d['-i'] == expected[user] and
                d['--cafile'].endswith('/phase8-4-2-lab/pki/ca.crt') and
                len(d['-P']) >= 16 and all(ch not in '\r\n\0' for ch in d['-P']),
                'identidade ou senha de laboratorio inesperada')
        result = {'-h': 'localhost', '-p': str(port),
                  '--cafile': str(scratch / 'files/legacy/certs/ca.crt'),
                  '-u': user, '-P': d['-P'], '-i': d['-i']}
        return ''.join(f'{k} {v}\n' for k, v in result.items()).encode('utf-8')
    except (ValueError, UnicodeError, KeyError):
        raise Block('credencial de laboratorio invalida') from None


def legacy_options(scratch: Path, user: str, port: int) -> bytes:
    require(user in ('bridge', 'lab'), 'identidade legada nao prevista')
    src = phase2.check_regular(scratch / f'files/legacy/mqtt-{user}.token', private=True)
    try:
        password = src.decode('ascii').strip('\r\n')
        require(len(password) >= 32 and len(password) < 1024 and
                all(33 <= ord(ch) <= 126 for ch in password) and '\n' not in password,
                'token legado invalido')
    except UnicodeError:
        raise Block('token legado invalido') from None
    return (f'-h localhost\n-p {port}\n--cafile {scratch / "files/legacy/certs/ca.crt"}\n'
            f'-u {user}\n-P {password}\n-i phase8453-{user}\n').encode('utf-8')


def options_file(scratch: Path, name: str, content: bytes) -> Path:
    phase2.mkdirs_locked(scratch, PurePosixPath('options'))
    target = scratch / 'options' / (name + '.opts')
    private_write(target, content)
    return target


def safe_run(argv: list[str], timeout=8) -> bool:
    try:
        p = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=timeout, check=False)
        return p.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def config_check(config: Path) -> None:
    require(safe_run(['mosquitto', '--test-config', '-c', str(config)], timeout=12),
            'configuracao de ensaio rejeitada por mosquitto --test-config')


@contextmanager
def broker(config: Path, port: int):
    require(port in (CANDIDATE, ROLLBACK) and available(port), 'porta de ensaio ocupada')
    proc = None
    try:
        proc = subprocess.Popen(['mosquitto', '-c', str(config)], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=False)
        until = time.monotonic() + 7
        while time.monotonic() < until:
            require(proc.poll() is None, 'broker do ensaio nao iniciou')
            if port_alive(port):
                break
            time.sleep(0.1)
        else:
            raise Block('broker de ensaio nao abriu o listener')
        yield
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()  # Only process spawned by this script.
                    proc.wait(timeout=4)
            # Confirm the port has been released.
            until = time.monotonic() + 2
            while not available(port) and time.monotonic() < until:
                time.sleep(0.1)
            require(available(port), 'processo de ensaio nao liberou a porta')


def mqtt_delivery(publisher: Path, subscriber: Path, topic: str) -> bool:
    """Publish one unique nonsecret payload; receive from authorized subscriber."""
    msg = ('phase8453-' + secrets.token_hex(8)).encode('ascii')
    sub = None
    try:
        sub = subprocess.Popen(['mosquitto_sub', '-o', str(subscriber), '-t', topic,
                                '-C', '1', '-W', '6', '-R'], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        time.sleep(0.6)
        if sub.poll() is not None:
            return False
        if not safe_run(['mosquitto_pub', '-o', str(publisher), '-t', topic,
                         '-q', '1', '-m', msg.decode('ascii')], timeout=7):
            return False
        received, _ = sub.communicate(timeout=7)
        return sub.returncode == 0 and received.strip() == msg
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        if sub is not None and sub.poll() is None:
            sub.terminate()
            try:
                sub.wait(timeout=2)
            except subprocess.TimeoutExpired:
                sub.kill()
                sub.wait(timeout=2)
        if sub is not None and sub.stdout is not None:
            sub.stdout.close()


def mqtt_denied(options: Path, topic: str) -> bool:
    """Only consider rejection after another account proved same broker TLS works."""
    return not safe_run(['mosquitto_pub', '-o', str(options), '-t', topic,
                         '-q', '1', '-m', 'fase8453-rejeicao'], timeout=5)


def run(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path) -> None:
    prereq(snapshot, backups, project, private, plugin)
    original_ports = probe_original()
    # scratch is private and outside Git. Its contents are deleted after all child processes exit.
    with tempfile.TemporaryDirectory(prefix='.ensaio-operacional-8453-', dir=backups) as temp:
        scratch = Path(temp)
        os.chmod(scratch, 0o700)
        restore_files(snapshot, scratch)
        candidate = build_candidate(snapshot, scratch, plugin)
        rollback = build_rollback(scratch)
        config_check(candidate)
        config_check(rollback)
        lab02 = options_file(scratch, 'lab02', parse_lab_options(scratch, 'device-sensor02', CANDIDATE))
        bridge = options_file(scratch, 'bridge-dyn', parse_lab_options(scratch, 'lab84-bridge', CANDIDATE))
        disabled = options_file(scratch, 'disabled-dyn', parse_lab_options(scratch, 'device-sensor01', CANDIDATE))
        old_lab = options_file(scratch, 'lab-legacy', legacy_options(scratch, 'lab', ROLLBACK))
        old_bridge = options_file(scratch, 'bridge-legacy', legacy_options(scratch, 'bridge', ROLLBACK))
        print('APROVADO: 20 arquivos recuperados em ambiente privado temporario; configs 8895/8896 validadas.')
        with broker(candidate, CANDIDATE):
            require(mqtt_delivery(lab02, bridge, 'lab/sensors/sensor02/telemetry'),
                    'candidato 8895 nao entregou mensagem sensor02 para bridge')
            require(mqtt_denied(disabled, 'lab/sensors/sensor01/telemetry'),
                    'sensor01 desabilitado conseguiu publicar no candidato')
            print('APROVADO: candidato 8895 TLS/MQTT, entrega sensor02->bridge e sensor01 bloqueado.')
        require(available(CANDIDATE), 'falha em interromper somente candidato')
        print('APROVADO: falha simulada; processo candidato encerrado e porta 8895 liberada.')
        with broker(rollback, ROLLBACK):
            require(mqtt_delivery(old_lab, old_bridge, 'lab/alerts'),
                    'rollback legado 8896 nao entregou mensagem lab->bridge')
            print('APROVADO: rollback isolado 8896 iniciou com password_file/ACL e entregou lab->bridge.')
        require(available(ROLLBACK), 'falha em interromper somente rollback')
    # Scratch removed automatically, and snapshot must remain unchanged.
    phase2.verify(snapshot, plugin)
    assert_origins_match(snapshot, project, private)
    require(original_ports == probe_original(), 'estado dos listeners 8883/8884 mudou durante o ensaio')
    require(available(CANDIDATE) and available(ROLLBACK), 'porta de ensaio permaneceu ocupada')
    print('APROVADO: snapshot imutavel, originais 8883/8884 inalterados, portas 8895/8896 liberadas.')
    print('RESULTADO: ENSAIO 8.4.5.3 APROVADO; rollback REAL do 8883 NAO TESTADO; corte NAO AUTORIZADO.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('preflight', 'simular'))
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home()/'.config/rust-server')
    parser.add_argument('--backups-root', type=Path, default=Path.home()/'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=phase2.PLUGIN)
    a = parser.parse_args()
    try:
        snap, backups, project, private, plugin = (
            x.absolute() for x in (a.snapshot, a.backups_root, a.project_root, a.private_root, a.plugin_path))
        if a.action == 'preflight':
            prereq(snap, backups, project, private, plugin)
            print('APROVADO: snapshot 8.4.5.2, plugin, ferramentas e portas 8895/8896 livres.')
            print('Nenhum broker iniciado; 8883 e 8884 nao serao alterados. Corte NAO AUTORIZADO.')
        else:
            run(snap, backups, project, private, plugin)
        return 0
    except (Block, phase2.Block) as error:
        print(f'BLOQUEIO: {error}. Nao repetir sem investigar; brokers originais nao sao controlados.',
              file=sys.stderr)
        return 2
    except (OSError, ValueError, subprocess.TimeoutExpired):
        print('BLOQUEIO: erro de sistema/ensaio; detalhes privados suprimidos. Nao fazer cutover.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
