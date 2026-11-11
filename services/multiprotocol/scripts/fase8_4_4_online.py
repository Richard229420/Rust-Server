#!/usr/bin/env python3
"""Fase 8.4.4: teste controlado de rotacao e revogacao ONLINE, apenas MQTT lab 8884.

preflight: leitura, sem alteracoes. apply: altera senha e desabilita sensor01, UMA VEZ.
after: prova que sensor01 permanece bloqueado e sensor02 segue operacional.
"""
from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time

import fase8_4_2_lab as lab

ROOT = lab.ROOT
STATE_NAME = 'fase8_4_4_state.json'
USERNAME = 'device-sensor01'
ALIVE = 'device-sensor02'
BRIDGE = 'lab84-bridge'
PERMITTED_KEYS = ('-h', '-p', '--cafile', '-u', '-P', '-i')


class Failure(Exception):
    pass


def ensure(condition, detail):
    if not condition:
        raise Failure(detail)


def private_file(path: Path):
    lab.check_private(path)
    ensure(not path.is_symlink() and path.stat().st_nlink == 1, 'Arquivo inseguro')


def load_options(username: str):
    ensure(username in (USERNAME, ALIVE, BRIDGE), 'Identidade inesperada')
    path = ROOT / 'clients' / (username + '.opts')
    private_file(path)
    result = {}
    for line in path.read_text(encoding='utf-8').splitlines():
        parts = line.split(' ', 1)
        ensure(len(parts) == 2 and parts[0] in PERMITTED_KEYS and parts[0] not in result, 'Opcao malformada/duplicada')
        result[parts[0]] = parts[1]
    ensure(tuple(result) == PERMITTED_KEYS, 'Ordem das opcoes nao corresponde ao laboratorio')
    ensure(result['-h'] == 'localhost' and result['-p'] == '8884', 'Conexao fora do laboratorio')
    ensure(Path(result['--cafile']) == ROOT / 'pki' / 'ca.crt', 'CA de outro ambiente')
    ensure(result['-u'] == username, 'Usuario inconsistente')
    expected_id = lab.CLIENTS[username][1]
    ensure(result['-i'] == expected_id, 'Client ID inconsistente')
    ensure(bool(result['-P']) and '\n' not in result['-P'], 'Senha invalida')
    return result


def encode_length(value):
    ensure(0 <= value <= 268435455, 'Tamanho MQTT invalido')
    out = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value:
            digit |= 0x80
        out.append(digit)
        if not value:
            return bytes(out)


def mqtt_utf8(value):
    data = value.encode('utf-8')
    ensure(len(data) < 65536, 'Campo MQTT grande demais')
    return len(data).to_bytes(2, 'big') + data


def packet(kind, body):
    return bytes([kind]) + encode_length(len(body)) + body


def recv_exact(sock, n):
    out = bytearray()
    while len(out) < n:
        data = sock.recv(n - len(out))
        if not data:
            raise Failure('Conexao MQTT encerrada antes da resposta')
        out.extend(data)
    return bytes(out)


def read_packet(sock):
    first = recv_exact(sock, 1)[0]
    n, mul = 0, 1
    for _ in range(4):
        v = recv_exact(sock, 1)[0]
        n += (v & 127) * mul
        if not (v & 128):
            break
        mul *= 128
    else:
        raise Failure('Comprimento MQTT invalido')
    ensure(n <= 8192, 'Pacote de broker maior que limite')
    return first, recv_exact(sock, n)


def connect_mqtt(options, *, client_id=None, password=None, allowed=True):
    """Handshake MQTT 3.1.1, com TLS e verificacao de SAN, sem pacotes extras."""
    client_id = client_id if client_id is not None else options['-i']
    password = password if password is not None else options['-P']
    context = ssl.create_default_context(cafile=options['--cafile'])
    context.check_hostname = True
    raw = socket.create_connection(('127.0.0.1', 8884), timeout=4)
    try:
        sock = context.wrap_socket(raw, server_hostname='localhost')
    except BaseException:
        raw.close()
        raise
    sock.settimeout(4)
    try:
        body = (mqtt_utf8('MQTT') + b'\x04\xc2\x00\x1e' +
                mqtt_utf8(client_id) + mqtt_utf8(options['-u']) + mqtt_utf8(password))
        sock.sendall(packet(0x10, body))
        kind, payload = read_packet(sock)
        ensure(kind == 0x20 and len(payload) == 2, 'CONNACK invalido: nao contar como bloqueio')
        if allowed:
            ensure(payload == b'\x00\x00', f'Autenticacao MQTT negada (codigo {payload[1]})')
            return sock
        ensure(payload[0] == 0 and payload[1] in (4, 5),
               f'Autenticacao NAO foi explicitamente rejeitada (codigo {payload[1]})')
        sock.close()
        return None
    except BaseException:
        sock.close()
        raise


def subscribe(sock, topic):
    sock.sendall(packet(0x82, b'\x00\x01' + mqtt_utf8(topic) + b'\x00'))
    kind, payload = read_packet(sock)
    ensure(kind == 0x90 and payload[:2] == b'\x00\x01' and payload[2:] == b'\x00',
           'SUBACK nao autorizou a assinatura')


def ping(sock):
    sock.sendall(b'\xc0\x00')
    kind, body = read_packet(sock)
    ensure(kind == 0xd0 and body == b'', 'PINGRESP ausente')


def publish_qos1(sender, receiver, message):
    topic = 'lab/sensors/sensor02/telemetry'
    payload = mqtt_utf8(topic) + b'\x00\x09' + message.encode('ascii')
    sender.sendall(packet(0x32, payload))
    kind, body = read_packet(sender)
    ensure(kind == 0x40 and body == b'\x00\x09', 'PUBACK do sensor02 nao recebido')
    kind, body = read_packet(receiver)
    ensure((kind & 0xf0) == 0x30, 'Bridge nao recebeu PUBLISH')
    ensure(body.startswith(mqtt_utf8(topic)), 'Topico inesperado recebido pela bridge')
    ensure(body.endswith(message.encode('ascii')), 'Payload nao entregue pela bridge')


def observe_disconnect(sock, seconds=6):
    deadline = time.monotonic() + seconds
    sock.settimeout(0.3)
    while time.monotonic() < deadline:
        try:
            data = sock.recv(1)
            if not data:
                return True
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, ssl.SSLZeroReturnError):
            return True
        except socket.timeout:
            continue
    return False


def state_file():
    return ROOT / STATE_NAME


def write_state(phase):
    path = state_file()
    if path.exists() or path.is_symlink():
        private_file(path)
    content = json.dumps({'phase': '8.4.4', 'stage': phase, 'target': USERNAME, 'port': 8884}, indent=2) + '\n'
    fd, name = tempfile.mkstemp(prefix='.phase844-', dir=ROOT)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def read_state():
    path = state_file()
    if not path.exists() and not path.is_symlink():
        return None
    private_file(path)
    state = json.loads(path.read_text(encoding='utf-8'))
    ensure(state.get('phase') == '8.4.4' and state.get('target') == USERNAME and state.get('port') == 8884,
           'Marcador de execucao inesperado')
    return state.get('stage')


def preflight():
    ensure(os.geteuid() != 0, 'Nunca execute com sudo/root')
    lab.validated_root()
    ensure(lab.port_open(8884), 'Broker laboratorio 8884 OFFLINE')
    ensure((ROOT / 'provisioned.json').is_file(), 'Execute fase 8.4.2 antes')
    ensure('plugin_use labdynsec' in (ROOT / 'mosquitto-lab.conf').read_text(), 'Plugin ausente na configuracao')
    opts = {name: load_options(name) for name in (USERNAME, ALIVE, BRIDGE)}
    ensure(os.path.isfile(ROOT / 'pki' / 'ca.crt'), 'CA do laboratorio ausente')
    return opts


def temp_admin_options(password):
    """Mantem senha do admin apenas em arquivo 0600 temporario, nao em argv."""
    return lab.secure_client_options(lab.ADMIN, 'lab84-admin-phase844', password)


def run_control(path, *args, input_text=None):
    command = ['mosquitto_ctrl', '-o', str(path), 'dynsec', *args]
    result = subprocess.run(command, input=input_text, capture_output=True, text=True, timeout=15, check=False)
    out = result.stdout + result.stderr
    ensure(result.returncode == 0 and 'Error:' not in out and 'error:' not in out,
           'Controle DynSec falhou; confira logs SEM compartilhar credenciais')


def snapshot_lab():
    """Copia privada das credenciais e do estado DynSec ANTES da mutacao.

    Nunca realizar restauracao em broker ativo. A copia e para resposta manual.
    """
    dest = ROOT / 'backup-fase8-4-4'
    ensure(not dest.exists() and not dest.is_symlink(),
           'Backup 8.4.4 ja existe: nao sobrescrever nem executar novamente')
    names = ['dynamic-security.json'] + ['clients/' + name + '.opts'
                                         for name in (USERNAME, ALIVE, BRIDGE)]
    payloads = {}
    for name in names:
        path = ROOT / name
        private_file(path)
        payloads[name] = path.read_bytes()
    # Reject corrupted/truncated plugin states before capturing rollback baseline.
    ensure(isinstance(json.loads(payloads['dynamic-security.json']), dict),
           'JSON do plugin invalido; nao alterar contas')
    dest.mkdir(mode=0o700)
    for name, blob in payloads.items():
        target = dest / name.replace('/', '__')
        fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        private_file(target)
        ensure(hashlib.sha256(target.read_bytes()).digest() == hashlib.sha256(blob).digest(),
               'Snapshot incompleto; interrompido')
    return dest


def pending_options(password):
    # Arquivo recuperavel se a chamada DynSec retornar sucesso mas a validacao falhar.
    body = lab.secure_client_options(USERNAME, lab.CLIENTS[USERNAME][1], password)
    fd, filename = tempfile.mkstemp(prefix='.sensor01-new-', suffix='.pending', dir=ROOT / 'clients')
    with os.fdopen(fd, 'w', encoding='utf-8') as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(body)
        fh.flush()
        os.fsync(fh.fileno())
    return Path(filename)


def apply():
    opts = preflight()
    ensure(read_state() is None, 'Fase 8.4.4 ja iniciada: nao repetir mutacoes; execute after/consulte docs')
    primary, second, bridge = (opts[x] for x in (USERNAME, ALIVE, BRIDGE))
    # Pedir senha ANTES de abrir sessoes persistentes: usuario pode levar tempo
    # para digitar, e um MQTT keepalive de 30s poderia expirar nesse intervalo.
    admin_password = getpass.getpass('Senha de lab84-admin (somente laboratorio): ')
    ensure(len(admin_password) >= 20, 'Senha administrativa com menos de 20 caracteres')
    with tempfile.TemporaryDirectory(prefix='.phase844-admin-', dir=ROOT) as tmp:
        ctrl_path = Path(tmp) / 'admin.opts'
        lab.safe_write(ctrl_path, temp_admin_options(admin_password))
        run_control(ctrl_path, 'getClient', USERNAME)
        # Fazer spoof do ID antes de abrir a sessao duradoura de sensor02:
        # evita que um broker com logica de takeover peculiar afete o controle positivo.
        connect_mqtt(primary, client_id='lab84-sensor02', allowed=False)
        with connect_mqtt(primary) as existing, connect_mqtt(second) as alive, connect_mqtt(bridge) as receiver:
            subscribe(existing, 'bus/sensors/sensor01/#')
            subscribe(receiver, 'lab/sensors/sensor02/#')
            publish_qos1(alive, receiver, 'fase844-before-' + secrets.token_hex(6))
            print('APROVADO: vinculo username/Client ID e sensor02 operacional.')
            snapshot_lab()
            print('APROVADO: copia privada inicial do laboratorio verificada (NUNCA restaurar online).')
            new_password = secrets.token_hex(32)
            pending = pending_options(new_password)
            write_state('prepared')
            # NAO passar senha nova em argv. mosquitto_ctrl faz prompt via stdin.
            run_control(ctrl_path, 'setClientPassword', USERNAME,
                        input_text=f'{new_password}\n{new_password}\n')
            write_state('rotation-requested')
            # Validacao positiva e negativa de autenticação, em vez de confiar no exit code da CLI.
            with connect_mqtt(primary, password=new_password) as fresh:
                ping(fresh)
            connect_mqtt(primary, password=primary['-P'], allowed=False)
            # Senha nova autenticou e senha antiga foi negada: atualizar arquivo local atomicamente.
            os.replace(pending, ROOT / 'clients' / (USERNAME + '.opts'))
            write_state('rotation-verified')
            print('APROVADO: senha nova aceita e senha antiga negada, sem reiniciar broker.')

            # Cliente conectado APOS rotacao; conta deve ser encerrada na revogacao.
            with connect_mqtt(primary, password=new_password) as connected:
                subscribe(connected, 'bus/sensors/sensor01/#')
                publish_qos1(alive, receiver, 'fase844-rotated-' + secrets.token_hex(6))
                run_control(ctrl_path, 'disableClient', USERNAME)
                write_state('disable-requested')
                ensure(observe_disconnect(connected), 'INCONCLUSIVO: sessao do sensor01 nao foi encerrada')
                print('APROVADO: sessao ativa de sensor01 foi desconectada apos disableClient.')
            connect_mqtt(primary, password=new_password, allowed=False)
            connect_mqtt(primary, password=primary['-P'], allowed=False)
            publish_qos1(alive, receiver, 'fase844-after-' + secrets.token_hex(6))
            ping(alive)
            ensure(lab.port_open(8884), 'Broker 8884 nao permaneceu online')
            write_state('completed')
            print('APROVADO: sensor01 bloqueado, sensor02 ativo e entregando, broker 8884 sem reinicio.')
            print('Estado final intencional: sensor01 DESABILITADO apenas em 8884. Nao execute 8.4.2 6/6 novamente.')


def after():
    opts = preflight()
    ensure(read_state() == 'completed', 'Marco 8.4.4 ainda nao concluido; nao interpretar como revogacao')
    connect_mqtt(opts[USERNAME], allowed=False)
    connect_mqtt(opts[USERNAME], client_id=opts[ALIVE]['-i'], allowed=False)
    with connect_mqtt(opts[ALIVE]) as alive, connect_mqtt(opts[BRIDGE]) as receiver:
        subscribe(receiver, 'lab/sensors/sensor02/#')
        publish_qos1(alive, receiver, 'fase844-aftercheck-' + secrets.token_hex(6))
    print('APROVADO: credencial desabilitada rejeitada, sensor02 publica e bridge recebe.')
    print('Porta 8883:', 'LISTEN' if lab.port_open(8883) else 'OFFLINE (nenhuma alteracao aplicada)')


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['preflight', 'apply', 'after'])
    args = p.parse_args()
    try:
        if args.action == 'preflight':
            preflight()
            print('APROVADO: preflight laboratorio 8884, contas e certificados privados.')
            print('Marcador:', read_state() or 'ausente (pronto para primeiro teste)')
        elif args.action == 'apply':
            apply()
        else:
            after()
    except (Failure, lab.Abort, TimeoutError, OSError, ValueError, subprocess.TimeoutExpired,
            ssl.SSLError, json.JSONDecodeError) as exc:
        # Nao imprimir excecoes do subprocess nem senhas; mensagens internas sao estaticas.
        if isinstance(exc, (Failure, lab.Abort)):
            print('REPROVADO:', str(exc), file=sys.stderr)
        else:
            print('INCONCLUSIVO: erro na comunicacao/estado; revisar log sem expor segredos.', file=sys.stderr)
        print('Se apply iniciou, NAO repita: examine stage no arquivo privado fase8_4_4_state.json.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
