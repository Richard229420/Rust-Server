#!/usr/bin/env python3
"""Rust-Server 8.4.5.4-B: ENSAIO de politica equivalente à producao, SOMENTE 8895.

Cria DynSec descartavel em scratch privado, provisiona identidades ficticias
com NOMES funcionais legados (mas SENHAS NOVAS e temporarias). NUNCA copia
senhas existentes nem modifica 8883/8884/snapshot/Git. Nao autoriza corte.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile

import fase8_4_5_1_auditoria as audit1
import fase8_4_5_2_preparar as p2
import fase8_4_5_3_ensaio as p3
import fase8_4_5_4_paridade as p4

PORT = 8895
HOST = '127.0.0.1'
ADMIN = 'phase8454b-admin'
ACCOUNTS = ('lab', 'bridge', 'device-sensor02')
IDS = {'lab': 'phase8454b-lab', 'bridge': 'phase8454b-bridge',
       'device-sensor02': 'phase8454b-sensor02'}
DEFAULTS = ('publishClientSend', 'publishClientReceive', 'subscribe', 'unsubscribe')

class Block(Exception):
    """Nunca incorpora dados de usuarios, tokens ou saida do broker na excecao."""


def need(ok: bool, message: str) -> None:
    if not ok:
        raise Block(message)


def role_name(username: str) -> str:
    need(username in ACCOUNTS, 'identidade fora do baseline')
    return 'phase8454b-role-' + username.replace('device-', '')


def permissions(legacy: dict[str, set[str]]) -> dict[str, tuple[tuple[str, str], ...]]:
    """Traduz o ACL LEGADO verificado; read = subscribe + receive, write = send."""
    need(set(legacy) == set(ACCOUNTS), 'usuarios ativos diferentes do inventario legado')
    expected = {
        **{k: set(v) for k, v in audit1.LEGACY_BASE.items()},
        'device-sensor02': {'write lab/sensors/sensor02/#', 'read bus/sensors/sensor02/#'},
    }
    need(legacy == expected, 'ACL de origem alterada; revisao obrigatoria')
    mapped = {}
    for user in ACCOUNTS:
        acls = []
        for rule in sorted(legacy[user]):
            action, topic = rule.split(' ', 1)
            need(topic not in ('#', '+') and not topic.startswith('$CONTROL') and
                 not topic.startswith('$SYS') and '#' not in topic[:-1],
                 'topico legado excessivamente permissivo')
            if action == 'write':
                acls.append(('publishClientSend', topic))
            elif action == 'read':
                acls.extend((('publishClientReceive', topic), ('subscribePattern', topic)))
            else:
                raise Block('permissao legada desconhecida')
        mapped[user] = tuple(sorted(acls))
    return mapped


def verify_plan(snapshot: Path, plugin: Path) -> dict[str, tuple[tuple[str, str], ...]]:
    """Somente leitura. Aceita as lacunas historicas do LAB mas exige baseline valido."""
    p2.verify(snapshot, plugin)
    base = snapshot / 'files'
    legacy = p4.legacy_acl(*(p2.check_regular(base / f, private=True)
                              for f in ('legacy/acl', 'legacy/devices.json', 'legacy/passwords')))
    return permissions(legacy)


def opts(ca: Path, user: str, password: str, clientid: str) -> bytes:
    need(user in ACCOUNTS or user == ADMIN, 'conta desconhecida')
    need(len(password) >= 32 and '\n' not in password and '\r' not in password,
         'credencial temporaria invalida')
    need(clientid and '\n' not in clientid, 'Client ID invalido')
    return (f'-h localhost\n-p {PORT}\n--cafile {ca}\n'
            f'-u {user}\n-P {password}\n-i {clientid}\n').encode('utf-8')


def init_dynsec(scratch: Path, state: Path, pw: str) -> None:
    need(state.parent == scratch / 'production-candidate' and not state.exists(),
         'estado candidato fora do scratch ou ja existente')
    # Both prompts via stdin; no secrets in argv or logs.
    call(['mosquitto_ctrl', 'dynsec', 'init', str(state), ADMIN],
         input_text=pw + '\n' + pw + '\n', timeout=20)
    os.chmod(state, 0o600)
    p2.check_regular(state, private=True)


def call(args: list[str], *, input_text: str | None = None, timeout: int = 10) -> None:
    """Fail closed, suppress outputs, never expose user secrets in argv."""
    need(args and args[0] in ('mosquitto_ctrl',), 'comando nao permitido')
    try:
        proc = subprocess.run(args, input=input_text, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, timeout=timeout, check=False)
        need(proc.returncode == 0 and 'Error:' not in proc.stdout and 'error:' not in proc.stdout,
             'operacao de provisionamento DynSec rejeitada')
    except (OSError, subprocess.TimeoutExpired):
        raise Block('ferramenta de provisionamento indisponivel') from None


def control(opts_file: Path, *arguments: str, input_text: str | None = None) -> None:
    need(arguments and arguments[0] in {
        'getDefaultACLAccess', 'setDefaultACLAccess', 'createRole', 'addRoleACL',
        'createClient', 'setClientId', 'addClientRole', 'getClient'},
        'comando DynSec nao previsto')
    call(['mosquitto_ctrl', '-o', str(opts_file), 'dynsec', *arguments], input_text=input_text)


def config(scratch: Path, plugin: Path) -> Path:
    folder = scratch / 'production-candidate'
    ca = scratch / 'files/legacy/certs'
    cfg = folder / 'mosquitto.conf'
    text = '\n'.join((
        '# FASE 8.4.5.4-B: CANDIDATO DESCARTAVEL. NAO USAR EM PRODUCAO',
        'persistence false', 'log_dest stderr', 'connection_messages false',
        'max_packet_size 8192', 'message_size_limit 2048',
        'max_queued_messages 64', 'max_queued_bytes 65536', 'max_connections 64',
        f'plugin_load phase8454b {plugin}',
        f'plugin_opt_config_file {folder / "dynamic-security.json"}',
        f'listener {PORT} {HOST}', 'listener_allow_anonymous false',
        f'certfile {ca / "localhost.crt"}', f'keyfile {ca / "localhost.key"}',
        'tls_version tlsv1.2', 'plugin_use phase8454b', '',
    ))
    need('8883' not in text and '8884' not in text, 'configuracao aponta ao broker original')
    p3.private_write(cfg, text.encode('utf-8'))
    return cfg


def verify_preview(state: Path, mapping: dict[str, tuple[tuple[str, str], ...]]) -> None:
    """Valida estritamente contas, ACLs e grupos herdados no arquivo descartavel."""
    try:
        data = json.loads(p2.check_regular(state, private=True))
    except (ValueError, UnicodeError):
        raise Block('estado DynSec temporario invalido') from None
    need(isinstance(data, dict), 'estado DynSec inesperado')
    need(isinstance(data.get('defaultACLAccess'), dict) and
         all(data['defaultACLAccess'].get(k) is False for k in DEFAULTS),
         'DEFAULT DENY incompleto')
    clients = p4.unique_by(data.get('clients'), 'username')
    roles = p4.unique_by(data.get('roles'), 'rolename')
    need(set(clients) == set(ACCOUNTS) | {ADMIN}, 'contas diferentes do candidato esperado')
    need('device-sensor01' not in clients and 'lab84-bridge' not in clients,
         'conta revogada ou conta experimental introduzida')
    for user in ACCOUNTS:
        client = clients[user]
        need(client.get('clientid', client.get('clientId')) == IDS[user],
             'Client ID nao vinculado no candidato')
        need(client.get('disabled', False) is False and
             p4.reference_names(client.get('roles'), 'rolename') == {role_name(user)} and
             not p4.reference_names(client.get('groups'), 'groupname'),
             'identidade com permissao adicional')
        role = roles.get(role_name(user))
        need(role is not None and isinstance(role.get('acls'), list), 'role ausente')
        found = set()
        for entry in role['acls']:
            need(isinstance(entry, dict) and entry.get('allow') is True and
                 isinstance(entry.get('acltype'), str) and isinstance(entry.get('topic'), str),
                 'ACL temporaria invalida')
            key = (entry['acltype'], entry['topic'])
            need(key not in found, 'ACL duplicada')
            found.add(key)
        need(found == set(mapping[user]), 'ACL candidata nao corresponde ao legado')


def wire_len(n: int) -> bytes:
    out = bytearray()
    while True:
        value = n & 0x7f
        n >>= 7
        out.append(value | (0x80 if n else 0))
        if not n:
            return bytes(out)


def field(text: str) -> bytes:
    raw = text.encode('utf-8')
    need(len(raw) < 65536, 'campo MQTT excede limite')
    return len(raw).to_bytes(2, 'big') + raw


def read_packet(tls: ssl.SSLSocket) -> tuple[int, bytes]:
    def exact(size: int) -> bytes:
        buf = bytearray()
        while len(buf) < size:
            more = tls.recv(size - len(buf))
            need(bool(more), 'conexao MQTT encerrada prematuramente')
            buf.extend(more)
        return bytes(buf)
    kind = exact(1)[0]
    length = 0
    mult = 1
    for _ in range(4):
        octet = exact(1)[0]
        length += (octet & 0x7f) * mult
        if not octet & 0x80:
            break
        mult *= 128
    else:
        raise Block('pacote MQTT malformado')
    need(length <= 8192, 'pacote MQTT muito grande')
    return kind, exact(length)


def mqtt5_check(ca: Path, username: str, password: str, cid: str,
                *, expect_auth: bool, deny_pub: str | None = None,
                deny_sub: str | None = None) -> None:
    """Verifica CONNACK ou razoes negativas MQTT v5 explicitas, nao timeout."""
    ctx = ssl.create_default_context(cafile=str(ca))
    with socket.create_connection((HOST, PORT), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname='localhost') as tls:
            tls.settimeout(5)
            variable = field('MQTT') + b'\x05\xc2\x00\x1e\x00' + field(cid) + field(username) + field(password)
            tls.sendall(b'\x10' + wire_len(len(variable)) + variable)
            kind, res = read_packet(tls)
            need(kind == 0x20 and len(res) >= 3, 'CONNACK MQTT ausente')
            reason = res[1]
            if not expect_auth:
                need(reason in (0x86, 0x87), 'conta invalida autenticou inesperadamente')
                return
            need(reason == 0, 'identidade ativa nao autenticou')
            if deny_pub is not None:
                payload = field(deny_pub) + b'\x00\x01\x00' + b'negado-8454b'
                tls.sendall(b'\x32' + wire_len(len(payload)) + payload)
                ack_type, ack = read_packet(tls)
                need(ack_type == 0x40 and len(ack) >= 3 and
                     ack[:2] == b'\x00\x01' and ack[2] == 0x87,
                     'publicacao proibida sem PUBACK 0x87')
            if deny_sub is not None:
                data = b'\x00\x02\x00' + field(deny_sub) + b'\x00'
                tls.sendall(b'\x82' + wire_len(len(data)) + data)
                typ, ack = read_packet(tls)
                need(typ == 0x90 and len(ack) >= 4 and ack[:2] == b'\x00\x02' and
                     ack[2] == 0 and ack[3] == 0x87,
                     'assinatura proibida sem SUBACK 0x87')


def preflight(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path):
    p3.prereq(snapshot, backups, project, private, plugin)
    p4.analyze(snapshot, plugin)  # validade TLS, DEFAULT DENY e lacunas historicas
    policy = verify_plan(snapshot, plugin)
    need(shutil.which('mosquitto_ctrl') is not None, 'mosquitto_ctrl nao instalado')
    return policy


def run(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path) -> None:
    mapping = preflight(snapshot, backups, project, private, plugin)
    status = p3.probe_original()
    with tempfile.TemporaryDirectory(prefix='.paridade-producao-8454b-', dir=backups) as temp:
        scratch = Path(temp)
        os.chmod(scratch, 0o700)
        p3.restore_files(snapshot, scratch)
        p2.mkdirs_locked(scratch, PurePosixPath('production-candidate'))
        folder = scratch / 'production-candidate'
        admin_pw = secrets.token_hex(32)
        state = folder / 'dynamic-security.json'
        init_dynsec(scratch, state, admin_pw)
        cfg = config(scratch, plugin)
        p3.config_check(cfg)
        ca = scratch / 'files/legacy/certs/ca.crt'
        ctrl = p3.options_file(scratch, '8454b-admin', opts(ca, ADMIN, admin_pw, 'phase8454b-admin'))
        password_by_user = {user: secrets.token_hex(32) for user in ACCOUNTS}
        options = {user: p3.options_file(scratch, '8454b-' + user,
                   opts(ca, user, password_by_user[user], IDS[user])) for user in ACCOUNTS}
        with p3.broker(cfg, PORT):
            control(ctrl, 'getDefaultACLAccess')
            for category in DEFAULTS:
                control(ctrl, 'setDefaultACLAccess', category, 'deny')
            for user in ACCOUNTS:
                role = role_name(user)
                control(ctrl, 'createRole', role)
                for acltype, topic in mapping[user]:
                    control(ctrl, 'addRoleACL', role, acltype, topic, 'allow', '10')
                pw = password_by_user[user]
                control(ctrl, 'createClient', user, input_text=pw + '\n' + pw + '\n')
                control(ctrl, 'setClientId', user, IDS[user])
                control(ctrl, 'addClientRole', user, role, '10')
            # Verify effective state through live broker login / resulting DynSec file.
            control(ctrl, 'getClient', 'bridge')
            verify_preview(state, mapping)
            need(p3.mqtt_delivery(options['lab'], options['bridge'], 'lab/alerts'),
                 'alerta lab->bridge nao entregue')
            need(p3.mqtt_delivery(options['bridge'], options['lab'], 'bus/alerts'),
                 'retorno bridge->lab nao entregue')
            need(p3.mqtt_delivery(options['device-sensor02'], options['bridge'],
                                  'lab/sensors/sensor02/telemetry'), 'telemetria nao entregue')
            need(p3.mqtt_delivery(options['bridge'], options['device-sensor02'],
                                  'bus/sensors/sensor02/status'), 'retorno do sensor nao entregue')
            print('APROVADO: contas funcionais lab, bridge e sensor02 com ACLs legadas no DynSec isolado 8895.')
            print('APROVADO: alertas e telemetria bidirecionais entregues com TLS estrito.')
            mqtt5_check(ca, 'device-sensor01', secrets.token_hex(32), 'phase8454b-revoked', expect_auth=False)
            mqtt5_check(ca, 'device-sensor02', password_by_user['device-sensor02'], IDS['bridge'], expect_auth=False)
            mqtt5_check(ca, 'device-sensor02', password_by_user['device-sensor02'], IDS['device-sensor02'],
                        expect_auth=True, deny_pub='lab/alerts', deny_sub='bus/alerts')
            mqtt5_check(ca, 'bridge', password_by_user['bridge'], IDS['bridge'],
                        expect_auth=True, deny_pub='lab/alerts')
            print('APROVADO: sensor01 revogado, Client ID alheio, publish e subscribe nao autorizados rejeitados.')
        # All temporary secrets expire when scratch is removed.
    p2.verify(snapshot, plugin)
    p3.assert_origins_match(snapshot, project, private)
    need(p3.probe_original() == status and p3.available(8895) and p3.available(8896),
         'portas ou estado dos brokers originais alterados')
    print('APROVADO: snapshot e brokers 8883/8884 preservados; 8895/8896 livres; contas descartadas.')
    print('PENDENTE: migrar/rotacionar credenciais reais; Client IDs reais; autorizacao de corte e CI/Git.')
    print('RESULTADO: PARIDADE DE POLITICAS ENSAIADA; MIGRACAO 8883 NAO AUTORIZADA.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('preflight', 'ensaiar'))
    parser.add_argument('--snapshot', required=True, type=Path)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home()/'.config/rust-server')
    parser.add_argument('--backups-root', type=Path, default=Path.home()/'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    args = parser.parse_args()
    try:
        snap, backup, project, private, plugin = (
            p.absolute() for p in (args.snapshot, args.backups_root, args.project_root,
                                   args.private_root, args.plugin_path))
        if args.action == 'preflight':
            mapping = preflight(snap, backup, project, private, plugin)
            print('APROVADO: snapshot, ACL legadas, certificados TLS e ferramentas verificados (somente leitura).')
            print(f'PREVISTO: {len(mapping)} identidades funcionais, 8895 temporaria, credenciais novas em scratch.')
            print('Corte 8883 NAO AUTORIZADO.')
        else:
            run(snap, backup, project, private, plugin)
        return 0
    except (Block, p2.Block, p3.Block, p4.Block) as err:
        print(f'BLOQUEIO: {err}. Nao executar cutover.', file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError, ssl.SSLError, subprocess.TimeoutExpired):
        print('BLOQUEIO: falha operacional isolada; detalhes sensiveis omitidos.', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
