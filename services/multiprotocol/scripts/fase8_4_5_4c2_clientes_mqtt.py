#!/usr/bin/env python3
"""8.4.5.4-C.2: lab CLI e sensor02 no DynSec DESCARTAVEL 127.0.0.1:8895.

Somente credenciais geradas na memoria e guardadas em scratch 0700 fora do Git.
Nao opera 8883/8884, nao altera cadastro C, nao autoriza cutover.
O ID de sensor02 neste ensaio NAO prova o ID do dispositivo real.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import subprocess
import socket
import ssl
import sys
import tempfile
from contextlib import contextmanager

import fase8_4_5_2_preparar as p2
import fase8_4_5_3_ensaio as p3
import fase8_4_5_4_paridade as p4
import fase8_4_5_4b_paridade_producao as p4b
import fase8_4_5_4c1_bridge_rust as c1
import fase8_4_5_4c_prontidao_corte as p4c

PORT = 8895
HOST = '127.0.0.1'
ACCOUNTS = ('lab', 'bridge', 'device-sensor02')
TARGETS = ('lab', 'device-sensor02')
ID_MAP = {'bridge': c1.BRIDGE_CLIENT_ID,
          'device-sensor02': 'phase8454c2-sensor02'}
LAB_IDS = ('phase8454c2-cli-a', 'phase8454c2-cli-b')
SECRET_LENGTH = 64


class Block(Exception):
    """Only static diagnostics; no user data or credentials in exceptions."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise Block(message)


def client_policy(user: str) -> str:
    need(user in ACCOUNTS, 'conta nao permitida')
    return 'cli-dinamico' if user == 'lab' else 'id-vinculado'


def validate_preview(state: Path, mapping: dict[str, tuple[tuple[str, str], ...]]) -> None:
    """Fail-closed on ACL expansion or accidental production ID binding."""
    try:
        data = json.loads(p2.check_regular(state, private=True))
    except (ValueError, UnicodeError):
        raise Block('estado DynSec descartavel malformado') from None
    need(isinstance(data, dict), 'estado DynSec nao e objeto')
    defaults = data.get('defaultACLAccess')
    need(isinstance(defaults, dict) and set(defaults) == set(p4b.DEFAULTS) and
         all(type(defaults[k]) is bool and defaults[k] is False for k in p4b.DEFAULTS),
         'DEFAULT DENY nao estrito')
    clients = p4.unique_by(data.get('clients'), 'username')
    roles = p4.unique_by(data.get('roles'), 'rolename')
    need(set(clients) == set(ACCOUNTS) | {p4b.ADMIN}, 'contas inesperadas no ensaio')
    need(set(mapping) == set(ACCOUNTS), 'politica legada inesperada')
    need(len(roles) == len(ACCOUNTS) + 1 and
         {p4b.role_name(u) for u in ACCOUNTS} <= set(roles), 'papel extra ou ausente')
    need(data.get('groups') in (None, []), 'grupos nao autorizados')
    for user in ACCOUNTS:
        entry = clients[user]
        expected_id = ID_MAP.get(user)
        actual_id = entry.get('clientid', entry.get('clientId'))
        need((not actual_id if user == 'lab' else actual_id == expected_id),
             'politica de Client ID alterada')
        need(entry.get('disabled', False) is False and
             p4.reference_names(entry.get('roles'), 'rolename') == {p4b.role_name(user)} and
             not p4.reference_names(entry.get('groups'), 'groupname'),
             'conta desabilitada ou privilegios herdados')
        role = roles.get(p4b.role_name(user))
        need(isinstance(role, dict) and isinstance(role.get('acls'), list),
             'papel ausente ou invalido')
        found: set[tuple[str, str]] = set()
        for acl in role['acls']:
            need(isinstance(acl, dict) and acl.get('allow') is True and
                 isinstance(acl.get('acltype'), str) and isinstance(acl.get('topic'), str),
                 'ACL inesperada ou deny extra')
            rule = (acl['acltype'], acl['topic'])
            need(rule not in found, 'ACL duplicada')
            found.add(rule)
        need(found == set(mapping[user]), 'ACL difere do legado verificado')


def private_opts(scratch: Path, ca: Path, user: str, password: str,
                 cid: str, label: str) -> Path:
    need(user in ACCOUNTS and cid and cid not in ('auto', 'random') and
         password and len(password) == SECRET_LENGTH and
         password.isascii() and password.isalnum(), 'opcoes MQTT invalidas')
    need(label.isascii() and label.replace('-', '').isalnum(), 'rotulo invalido')
    return p3.options_file(scratch, 'c2-' + label,
                           p4b.opts(ca, user, password, cid))


def dyn_change(admin: Path, operation: str, user: str, *, password: str | None = None) -> None:
    need(user in TARGETS and operation in ('disableClient', 'enableClient', 'setClientPassword'),
         'acao administrativa nao autorizada')
    if operation == 'setClientPassword':
        need(isinstance(password, str) and len(password) == SECRET_LENGTH and
             password.isascii() and password.isalnum(), 'credencial temporaria invalida')
        input_text = password + '\n' + password + '\n'
    else:
        need(password is None, 'credencial nao esperada')
        input_text = None
    p4b.call(['mosquitto_ctrl', '-o', str(admin), 'dynsec', operation, user],
             input_text=input_text, timeout=15)


@contextmanager
def session(ca: Path, username: str, password: str, cid: str):
    """MQTT 5 CONNECT with explicit CONNACK; only isolated TLS port."""
    need(username in TARGETS and cid in (*LAB_IDS, ID_MAP['device-sensor02']),
         'sessao fora de escopo')
    ctx = ssl.create_default_context(cafile=str(ca))
    with socket.create_connection((HOST, PORT), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname='localhost') as tls:
            tls.settimeout(5)
            payload = (p4b.field('MQTT') + b'\x05\xc2\x00\x0a\x00' +
                       p4b.field(cid) + p4b.field(username) + p4b.field(password))
            tls.sendall(b'\x10' + p4b.wire_len(len(payload)) + payload)
            typ, ack = p4b.read_packet(tls)
            need(typ == 0x20 and len(ack) >= 3 and ack[1] == 0,
                 'CONNACK positivo ausente')
            yield tls


def ping_session(tls: ssl.SSLSocket) -> None:
    """Confirm an existing session is still live while another lab ID connects."""
    tls.sendall(b'\xc0\x00')
    kind, payload = p4b.read_packet(tls)
    need(kind == 0xd0 and payload == b'', 'sessao CLI compartilhada foi interrompida')


def expect_session_kicked(tls: ssl.SSLSocket) -> None:
    """A timeout is NOT evidence of an enforced disconnect."""
    tls.settimeout(6)
    try:
        response = tls.recv(1)
    except socket.timeout:
        raise Block('conexao ainda ativa apos revogacao') from None
    except (ssl.SSLEOFError, ConnectionResetError, BrokenPipeError):
        return
    need(response in (b'', b'\xe0'),
         'sessao MQTT permanece ativa apos disableClient')


def auth(ca: Path, user: str, password: str, cid: str, allowed: bool) -> None:
    need(user in (*TARGETS, 'device-sensor01') and cid and len(password) >= 32,
         'teste MQTT fora do escopo')
    p4b.mqtt5_check(ca, user, password, cid, expect_auth=allowed)


def exercise_delivery(scratch: Path, ca: Path, passwords: dict[str, str],
                      *, lab_id: str, sensor_id: str, stage: str) -> None:
    need(lab_id in LAB_IDS and sensor_id == ID_MAP['device-sensor02'],
         'Client ID temporario inesperado')
    files = {user: private_opts(scratch, ca, user, passwords[user],
             lab_id if user == 'lab' else ID_MAP[user], stage + '-' + user)
             for user in ACCOUNTS}
    need(p3.mqtt_delivery(files['lab'], files['bridge'], 'lab/alerts'),
         'alerta lab -> bridge nao entregue')
    need(p3.mqtt_delivery(files['bridge'], files['lab'], 'bus/alerts'),
         'alerta bridge -> lab nao entregue')
    need(p3.mqtt_delivery(files['device-sensor02'], files['bridge'],
                          'lab/sensors/sensor02/telemetry'),
         'telemetria sensor02 -> bridge nao entregue')
    need(p3.mqtt_delivery(files['bridge'], files['device-sensor02'],
                          'bus/sensors/sensor02/status'),
         'resposta bridge -> sensor02 nao entregue')


def preflight(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path):
    p4c.verify_branch(project)
    mapping = p4b.preflight(snapshot, backups, project, private, plugin)
    need(p3.available(PORT) and c1.listener_absent(PORT) and c1.listener_absent(8896),
         'porta temporaria ocupada')
    # No on-disk changes here; 8883 and 8884 are never started or stopped.
    return mapping


def run(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path) -> None:
    mapping = preflight(snapshot, backups, project, private, plugin)
    before = p3.probe_original()
    with tempfile.TemporaryDirectory(prefix='.clientes-8454c2-', dir=backups) as temp:
        scratch = Path(temp)
        os.chmod(scratch, 0o700)
        p3.restore_files(snapshot, scratch)
        p2.mkdirs_locked(scratch, PurePosixPath('production-candidate'))
        folder = scratch / 'production-candidate'
        admin_password = secrets.token_hex(32)
        state = folder / 'dynamic-security.json'
        p4b.init_dynsec(scratch, state, admin_password)
        cfg = p4b.config(scratch, plugin)
        p3.config_check(cfg)
        ca = scratch / 'files/legacy/certs/ca.crt'
        admin = private_opts_admin(scratch, ca, admin_password)
        initial = {name: secrets.token_hex(32) for name in ACCOUNTS}
        with c1.broker_for_bridge(cfg, PORT):
            for category in p4b.DEFAULTS:
                p4b.control(admin, 'setDefaultACLAccess', category, 'deny')
            for user in ACCOUNTS:
                role = p4b.role_name(user)
                p4b.control(admin, 'createRole', role)
                for action, topic in mapping[user]:
                    p4b.control(admin, 'addRoleACL', role, action, topic, 'allow', '10')
                password = initial[user]
                p4b.control(admin, 'createClient', user,
                            input_text=password + '\n' + password + '\n')
                if user != 'lab':
                    p4b.control(admin, 'setClientId', user, ID_MAP[user])
                p4b.control(admin, 'addClientRole', user, role, '10')
            validate_preview(state, mapping)
            print('APROVADO: candidato 8895 DEFAULT DENY, ACLs legadas; lab sem vinculo de ID e sensor02 com ID fixo TEMPORARIO.')
            auth(ca, 'lab', initial['lab'], LAB_IDS[0], True)
            auth(ca, 'lab', initial['lab'], LAB_IDS[1], True)
            with session(ca, 'lab', initial['lab'], LAB_IDS[0]) as cli_first:
                with session(ca, 'lab', initial['lab'], LAB_IDS[1]) as cli_second:
                    ping_session(cli_first)
                    ping_session(cli_second)
            auth(ca, 'device-sensor02', initial['device-sensor02'], ID_MAP['device-sensor02'], True)
            auth(ca, 'device-sensor02', initial['device-sensor02'], LAB_IDS[0], False)
            auth(ca, 'device-sensor01', secrets.token_hex(32), 'phase8454c2-revoked', False)
            p4b.mqtt5_check(ca, 'lab', initial['lab'], LAB_IDS[0], expect_auth=True,
                            deny_pub='lab/sensors/sensor02/telemetry',
                            deny_sub='bus/sensors/sensor02/#')
            p4b.mqtt5_check(ca, 'device-sensor02', initial['device-sensor02'], ID_MAP['device-sensor02'],
                            expect_auth=True, deny_pub='lab/alerts', deny_sub='bus/alerts')
            print('APROVADO: dois IDs CLI distintos para lab, sensor02 vinculado, sensor01 revogado; ACLs cruzadas negadas por MQTT 5.')
            exercise_delivery(scratch, ca, initial, lab_id=LAB_IDS[0],
                              sensor_id=ID_MAP['device-sensor02'], stage='baseline')
            print('APROVADO: alertas lab e telemetria sensor02 entregues em ambos os sentidos.')
            for user in TARGETS:
                cid = LAB_IDS[0] if user == 'lab' else ID_MAP[user]
                with session(ca, user, initial[user], cid) as live:
                    dyn_change(admin, 'disableClient', user)
                    expect_session_kicked(live)
                auth(ca, user, initial[user], cid, False)
                dyn_change(admin, 'enableClient', user)
                auth(ca, user, initial[user], cid, True)
                newer = secrets.token_hex(32)
                dyn_change(admin, 'setClientPassword', user, password=newer)
                auth(ca, user, initial[user], cid, False)
                auth(ca, user, newer, cid, True)
                rotated = {**initial, user: newer}
                exercise_delivery(scratch, ca, rotated,
                                  lab_id=LAB_IDS[1] if user == 'lab' else LAB_IDS[0],
                                  sensor_id=ID_MAP['device-sensor02'], stage='rotated-' + user)
                dyn_change(admin, 'setClientPassword', user, password=initial[user])
                auth(ca, user, newer, cid, False)
                auth(ca, user, initial[user], cid, True)
                exercise_delivery(scratch, ca, initial, lab_id=LAB_IDS[0],
                                  sensor_id=ID_MAP['device-sensor02'], stage='rollback-' + user)
                validate_preview(state, mapping)
                print('APROVADO: ' + user + ' — sessao derrubada no disable, reabilitacao, rotacao e retorno de senha temporaria.')
        # Child process closed and absence of listening checked before scratch is deleted.
    p2.verify(snapshot, plugin)
    p3.assert_origins_match(snapshot, project, private)
    need(p3.probe_original() == before and c1.listener_absent(PORT) and c1.listener_absent(8896),
         'listeners temporarios ou originais divergentes')
    print('APROVADO: processo temporario encerrado, 8895/8896 sem listener, snapshot e originais preservados.')
    print('LIMITE: IDs e senhas deste teste sao FICTICIOS; clientes reais lab/sensor02 nao foram observados nem alterados.')
    print('PENDENTE: cadastro C, credenciais reais, janela/rollback cliente, auditoria Seguranca e Git/CI.')
    print('RESULTADO: C.2 ENSAIO DE POLITICAS E RECONEXAO APROVADO; CORTE 8883 NAO AUTORIZADO.')


def private_opts_admin(scratch: Path, ca: Path, password: str) -> Path:
    return p3.options_file(scratch, 'c2-admin',
                           p4b.opts(ca, p4b.ADMIN, password, 'phase8454c2-admin'))


def inventory(project: Path) -> None:
    """Read-only code facts; does NOT infer runtime identities."""
    source = p2.check_regular(project / 'src/bridge.rs', private=False)
    need(b'MqttOptions::new("rust-server-bridge-local", "localhost", broker.port())' in source and
         b'options.set_credentials("bridge", password)' in source,
         'codigo bridge diverge do baseline C.1')
    print('DECLARADO: bridge Rust usa usuario bridge e ID rust-server-bridge-local (fonte, nao observacao ao vivo).')
    print('DECLARADO: scripts CLI usam opcoes -i variaveis/temporarias; nao comprovam Client ID de producao.')
    print('PENDENTE: identificar cliente real lab e configuracao efetiva do device-sensor02 fora do repo.')
    print('LIMITE: leitura do codigo nao equivale a evidencia de conexao ativa.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('preflight', 'inventariar', 'ensaiar'))
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--backups-root', type=Path, default=Path.home() / 'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    args = parser.parse_args()
    try:
        snapshot, backups, project, private, plugin = (p.absolute() for p in (
            args.snapshot, args.backups_root, args.project_root, args.private_root, args.plugin_path))
        mapping = None
        if args.action == 'inventariar':
            p4c.verify_branch(project)
            mapping = p4b.verify_plan(snapshot, plugin)
            need(set(mapping) == set(ACCOUNTS), 'baseline inesperado')
            inventory(project)
        elif args.action == 'preflight':
            preflight(snapshot, backups, project, private, plugin)
            print('APROVADO: snapshot, ACL legada, TLS, ferramentas e portas temporarias verificados (somente leitura).')
            print('PREVISTO: lab CLI com IDs variaveis; sensor02 com ID fixo SOMENTE no ensaio.')
            print('Corte 8883 NAO AUTORIZADO.')
        else:
            run(snapshot, backups, project, private, plugin)
        return 0
    except (Block, p2.Block, p3.Block, p4.Block, p4b.Block, c1.Block, p4c.Block):
        print('BLOQUEIO: ensaio C.2 interrompido; nenhum corte foi autorizado.', file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError, ssl.SSLError, subprocess.TimeoutExpired):
        print('BLOQUEIO: falha operacional C.2; detalhes privados omitidos.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
