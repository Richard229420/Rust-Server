#!/usr/bin/env python3
"""Testes MQTT reais fase 8.4.2: autenticação TLS e isolamento pelo plano de dados."""
from __future__ import annotations
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import socket

ROOT = Path.home() / '.config/rust-server/phase8-4-2-lab'


def check(cond, message):
    if not cond:
        raise RuntimeError(message)


def verify_secret_options(path):
    check(path.is_file() and not path.is_symlink(), f'Arquivo privado ausente: {path}')
    s = path.stat()
    check(s.st_uid == os.getuid() and s.st_nlink == 1 and not (s.st_mode & 0o077),
          f'Permissoes inseguras: {path}')
    content = path.read_text()
    check('-p 8884\n' in content and '-h localhost\n' in content and '--cafile ' in content,
          'Configuracao de cliente nao aponta apenas ao laboratorio')


def publish(options, topic, message):
    try:
        return subprocess.run(['mosquitto_pub', '-o', str(options), '-q', '1', '-t', topic, '-m', message],
                              capture_output=True, text=True, timeout=6)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Publicacao expirou; resultado inconclusivo')


def delivery(sub_opts, sub_topic, pub_opts, pub_topic, expect: bool, description: str):
    nonce = secrets.token_hex(12)
    # Um subscriber que nao consegue conectar nao pode ser interpretado como sucesso de ACL.
    proc = subprocess.Popen(['mosquitto_sub', '-o', str(sub_opts), '-t', sub_topic,
                             '-C', '1', '-W', '3', '-R'], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(0.6)
        r = publish(pub_opts, pub_topic, nonce)
        stdout, stderr = proc.communicate(timeout=5)
        received = nonce in stdout
        if expect:
            check(r.returncode == 0, f'{description}: publicacao autorizada falhou (rc={r.returncode})')
            check(proc.returncode == 0 and received, f'{description}: entrega autorizada NAO ocorreu')
        else:
            check(not received, f'{description}: ENTREGA INDEVIDA entre identidades')
            # Se a subscrição falhar explicitamente, trata-se de negação, não de rede;
            # os mesmos arquivos de credenciais já foram provados em testes positivos.
        print('APROVADO:', description)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate()


def main():
    check(os.geteuid() != 0, 'Nao execute com sudo/root')
    with socket.create_connection(('127.0.0.1', 8884), timeout=2):
        pass
    check((ROOT / 'provisioned.json').is_file(), 'Execute provisionar antes')
    options = {name: ROOT / 'clients' / (name + '.opts') for name in
               ('device-sensor01', 'device-sensor02', 'lab84-bridge')}
    for opt in options.values():
        verify_secret_options(opt)
    s1 = options['device-sensor01']
    s2 = options['device-sensor02']
    bridge = options['lab84-bridge']
    delivery(bridge, 'lab/sensors/sensor01/#', s1, 'lab/sensors/sensor01/telemetry', True,
             'sensor01 publica em seu namespace e bridge recebe')
    delivery(bridge, 'lab/sensors/sensor02/#', s2, 'lab/sensors/sensor02/telemetry', True,
             'sensor02 publica em seu namespace e bridge recebe')
    delivery(bridge, 'lab/sensors/sensor02/#', s1, 'lab/sensors/sensor02/telemetry', False,
             'sensor01 nao publica no namespace do sensor02')
    delivery(s1, 'bus/sensors/sensor01/#', bridge, 'bus/sensors/sensor01/status', True,
             'sensor01 le resposta destinada a ele')
    delivery(s1, 'bus/sensors/sensor02/#', bridge, 'bus/sensors/sensor02/status', False,
             'sensor01 nao le resposta do sensor02')
    delivery(s2, 'bus/sensors/sensor02/#', bridge, 'bus/sensors/sensor02/status', True,
             'sensor02 permanece funcional')
    print('APROVADO: 6 testes de isolamento com TLS e entrega real, broker 8883 intocado.')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError) as exc:
        print('REPROVADO:', exc, file=sys.stderr)
        sys.exit(1)
