#!/usr/bin/env python3
"""Rust-Server 8.4.5.4: auditoria de paridade TLS e ACL em COPIAS privadas.

'preflight' verifica snapshot, roles, contas e certificados, sem iniciar processos.
'ensaiar' verifica broker candidato 8895 e rollback 8896 em scratch temporario.
JAMAIS altera 8883, 8884, o snapshot ou os dados no repositorio.
LACUNAS de migracao de credenciais nao sao tratadas como aprovacao de corte.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
from typing import Any

import fase8_4_5_1_auditoria as audit1
import fase8_4_5_2_preparar as p2
import fase8_4_5_3_ensaio as p3

HOST = '127.0.0.1'
EXPECTED_CLIENTS = {
    'device-sensor01': ('lab84-sensor01', 'role-sensor01', True),
    'device-sensor02': ('lab84-sensor02', 'role-sensor02', False),
    'lab84-bridge': ('lab84-bridge', 'role-bridge', False),
}
EXPECTED_ACLS = {
    'role-sensor01': {
        ('publishClientSend', 'lab/sensors/sensor01/#'),
        ('publishClientReceive', 'bus/sensors/sensor01/#'),
        ('subscribePattern', 'bus/sensors/sensor01/#'),
    },
    'role-sensor02': {
        ('publishClientSend', 'lab/sensors/sensor02/#'),
        ('publishClientReceive', 'bus/sensors/sensor02/#'),
        ('subscribePattern', 'bus/sensors/sensor02/#'),
    },
    'role-bridge': {
        ('publishClientSend', 'bus/sensors/#'),
        ('publishClientReceive', 'lab/sensors/#'),
        ('subscribePattern', 'lab/sensors/#'),
    },
}
REQUIRED_DEFAULTS = ('publishClientSend', 'publishClientReceive', 'subscribe', 'unsubscribe')
LEGACY_IDENTITIES = {'lab', 'bridge', 'device-sensor02'}

class Block(Exception):
    """Only use fixed error messages. Never display sensitive JSON or command stderr."""


def demand(condition: bool, msg: str) -> None:
    if not condition:
        raise Block(msg)


def unique_by(items: Any, field: str) -> dict[str, dict]:
    demand(isinstance(items, list) and len(items) <= 64, 'colecao de politica inesperada')
    out = {}
    for item in items:
        demand(isinstance(item, dict) and isinstance(item.get(field), str), 'entrada de politica invalida')
        name = item[field]
        demand(name and name not in out and len(name) <= 80, 'entrada duplicada ou invalida')
        out[name] = item
    return out


def reference_names(items: Any, key: str) -> set[str]:
    if items is None:
        return set()
    demand(isinstance(items, list), 'referencias de identidade invalidas')
    names = set()
    for entry in items:
        demand(isinstance(entry, dict) and isinstance(entry.get(key), str), 'referencia de identidade invalida')
        name = entry[key]
        demand(name not in names, 'referencia duplicada')
        names.add(name)
    return names


def validate_dynsec(content: bytes) -> dict[str, set[str]]:
    """Fail closed for the expected lab accounts and effective role ACLs. Does not print JSON."""
    try:
        obj = json.loads(content)
    except (ValueError, UnicodeError):
        raise Block('JSON DynSec invalido') from None
    demand(isinstance(obj, dict), 'JSON DynSec inesperado')
    defaults = obj.get('defaultACLAccess')
    demand(isinstance(defaults, dict) and all(defaults.get(k) is False for k in REQUIRED_DEFAULTS),
           'Dynamic Security sem DEFAULT DENY nos quatro controles')
    clients = unique_by(obj.get('clients'), 'username')
    roles = unique_by(obj.get('roles'), 'rolename')
    groups = unique_by(obj.get('groups', []), 'groupname')
    demand('lab84-admin' in clients, 'conta administrativa de laboratorio ausente')
    demand(set(clients) == set(EXPECTED_CLIENTS) | {'lab84-admin'},
           'contas do laboratorio nao correspondem ao inventario esperado')
    demand(not {'lab', 'bridge'} & set(clients), 'conta legada foi introduzida no laboratorio')
    for name, (clientid, rolename, disabled) in EXPECTED_CLIENTS.items():
        client = clients[name]
        cid = client.get('clientid', client.get('clientId'))
        demand(cid == clientid, 'Client ID do laboratorio divergente')
        demand(client.get('disabled', False) is disabled, 'revogacao DynSec divergente')
        direct = reference_names(client.get('roles'), 'rolename')
        demand(direct == {rolename}, 'papel efetivo de dispositivo/bridge inesperado')
        assigned_groups = reference_names(client.get('groups'), 'groupname')
        demand(not assigned_groups, 'grupo adicional em dispositivo/bridge: validar heranca')
        demand(rolename in roles, 'papel exigido ausente')
        acl_entries = roles[rolename].get('acls')
        demand(isinstance(acl_entries, list), 'ACL do papel ausente')
        found = set()
        for entry in acl_entries:
            demand(isinstance(entry, dict) and entry.get('allow') is True and
                   isinstance(entry.get('acltype'), str) and isinstance(entry.get('topic'), str),
                   'ACL de papel invalida')
            item = (entry['acltype'], entry['topic'])
            demand(item not in found, 'ACL duplicada no papel')
            found.add(item)
        demand(found == EXPECTED_ACLS[rolename], 'ACL DynSec nao equivale ao perfil minimo do laboratorio')
    # Unknown group inheritance for the lab admin must not grant devices privileges.
    for group in groups.values():
        demand(isinstance(group.get('roles', []), list), 'grupo DynSec malformado')
    return {'clients': set(clients), 'roles': set(roles), 'groups': set(groups)}


def legacy_acl(content: bytes, devices: bytes, passwords: bytes) -> dict[str, set[str]]:
    try:
        inv = audit1.verify_inventory(devices)
        acl = audit1.acl_rules(content)
        users = audit1.usernames(passwords)
    except (audit1.Invalid, ValueError):
        raise Block('politica legada invalida') from None
    demand(inv.get('sensor01') == 'revoked' and inv.get('sensor02') == 'active',
           'inventario legado nao corresponde ao baseline')
    demand(audit1.compare_acl(acl, inv), 'ACL legada diverge do baseline 8.3')
    demand(users == LEGACY_IDENTITIES, 'usuarios legados nao correspondem ao baseline')
    return acl


def compare_identity_sets(legacy: dict[str, set[str]], dyn: dict[str, set[str]]) -> dict[str, bool]:
    # Deliberately mark these as gaps, NOT equivalent security policies.
    dyn_names = dyn['clients'] - {'lab84-admin'}
    return {
        'sensor02_username_presente': 'device-sensor02' in legacy and 'device-sensor02' in dyn_names,
        'identidades_iguais': set(legacy) == dyn_names,
        'conta_lab_presente': 'lab' in dyn_names,
        'conta_bridge_presente': 'bridge' in dyn_names,
        'namespace_alertas_equivalente': False,  # lab roles do not contain legacy alert ACLs
        'credenciais_producao_migradas': False,  # 20-file snapshot has no per-device credential export
    }


def verify_cert(ca: Path, leaf: Path, key: Path, *, name: str) -> None:
    """Cryptographic X509_STRICT, hostname, chain, validity, SAN and key match; no private contents printed."""
    for path in (ca, leaf, key):
        p2.check_regular(path, private=True)
    def run(args: list[str]) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise Block(f'TLS {name}: ferramenta de verificacao indisponivel') from None
    result = run(['openssl', 'verify', '-x509_strict', '-purpose', 'sslserver',
                  '-verify_hostname', 'localhost', '-CAfile', str(ca), str(leaf)])
    demand(result.returncode == 0, f'TLS {name}: cadeia/hostname/X509_STRICT reprovado')
    result = run(['openssl', 'x509', '-in', str(leaf), '-checkend', '0', '-noout'])
    demand(result.returncode == 0, f'TLS {name}: certificado expirado')
    ext = run(['openssl', 'x509', '-in', str(leaf), '-noout', '-ext', 'subjectAltName'])
    demand(ext.returncode == 0 and b'DNS:localhost' in ext.stdout,
           f'TLS {name}: SAN localhost ausente')
    public_cert = run(['openssl', 'x509', '-in', str(leaf), '-noout', '-pubkey'])
    public_key = run(['openssl', 'pkey', '-in', str(key), '-pubout'])
    demand(public_cert.returncode == 0 and public_key.returncode == 0 and
           public_cert.stdout.strip() == public_key.stdout.strip(), f'TLS {name}: chave nao corresponde')


def analyze(snapshot: Path, plugin: Path) -> dict[str, bool]:
    p2.verify(snapshot, plugin)
    base = snapshot / 'files'
    legacy = legacy_acl(*(
        p2.check_regular(base / path, private=True) for path in
        ('legacy/acl', 'legacy/devices.json', 'legacy/passwords')))
    dyn = validate_dynsec(p2.check_regular(base / 'lab/dynamic-security.json', private=True))
    gaps = compare_identity_sets(legacy, dyn)
    verify_cert(base / 'lab/pki/ca.crt', base / 'lab/pki/server.crt', base / 'lab/pki/server.key', name='laboratorio')
    verify_cert(base / 'legacy/certs/ca.crt', base / 'legacy/certs/localhost.crt',
                base / 'legacy/certs/localhost.key', name='legado/candidato')
    return gaps


def report(gaps: dict[str, bool]) -> None:
    print('APROVADO: snapshot 20 arquivos, ACL legada e politicas minimas DynSec validadas offline.')
    print('APROVADO: DEFAULT DENY, roles, Client IDs e revogacao sensor01 no snapshot.')
    print('APROVADO: TLS X509_STRICT, SAN localhost, validade e chave/certificado verificados.')
    print('INFO: contas funcionais legadas e contas de laboratorio sao distintas.')
    for code, result in gaps.items():
        if result:
            print('APROVADO: compatibilidade parcial de identificador sensor02 (nao senha).')
        else:
            messages = {
                'identidades_iguais': 'conjunto de identidades nao coincide (lab/bridge versus lab84-bridge)',
                'conta_lab_presente': 'conta lab de producao ausente do candidato',
                'conta_bridge_presente': 'conta bridge de producao ausente do candidato',
                'namespace_alertas_equivalente': 'topicos de alertas legados ainda nao modelados em DynSec',
                'credenciais_producao_migradas': 'credenciais de producao nao foram migradas/provisionadas',
                'sensor02_username_presente': 'sensor02 sem identidade comum',
            }
            print('LACUNA: ' + messages[code])
    print('RESULTADO: PARIDADE LABORATORIAL VERIFICADA; PARIDADE DE PRODUCAO PENDENTE.')
    print('Corte 8883 NAO AUTORIZADO; a auditoria nao cria identidades ou altera brokers.')


def cli_preflight(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path) -> dict[str, bool]:
    p3.prereq(snapshot, backups, project, private, plugin)
    return analyze(snapshot, plugin)


def run_lab(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path) -> None:
    gaps = cli_preflight(snapshot, backups, project, private, plugin)
    orig = p3.probe_original()
    # Temporary copy of the entire snapshot; no broker is pointed at a source path.
    with tempfile.TemporaryDirectory(prefix='.paridade-8454-', dir=backups) as tmp:
        scratch = Path(tmp)
        os.chmod(scratch, 0o700)
        p3.restore_files(snapshot, scratch)
        candidate = p3.build_candidate(snapshot, scratch, plugin)
        rollback = p3.build_rollback(scratch)
        p3.config_check(candidate)
        p3.config_check(rollback)
        s02 = p3.options_file(scratch, 'sensor02', p3.parse_lab_options(scratch,'device-sensor02',8895))
        bridge = p3.options_file(scratch, 'bridge', p3.parse_lab_options(scratch,'lab84-bridge',8895))
        s01 = p3.options_file(scratch, 'sensor01', p3.parse_lab_options(scratch,'device-sensor01',8895))
        old_lab = p3.options_file(scratch, 'old-lab', p3.legacy_options(scratch,'lab',8896))
        old_bridge = p3.options_file(scratch, 'old-bridge', p3.legacy_options(scratch,'bridge',8896))
        with p3.broker(candidate, 8895):
            demand(p3.mqtt_delivery(s02, bridge, 'lab/sensors/sensor02/telemetry'),
                   'candidato: telemetria sensor02 nao recebida')
            demand(p3.mqtt_delivery(bridge, s02, 'bus/sensors/sensor02/status'),
                   'candidato: retorno da bridge nao recebido')
            demand(p3.mqtt_denied(s01, 'lab/sensors/sensor01/telemetry'),
                   'candidato: sensor01 revogado publicou')
            # Stronger negative: existing active sensor02 must not publish other namespace.
            mqtt5_puback_denied(s02, 'lab/sensors/sensor01/telemetry', 8895, scratch/'files/legacy/certs/ca.crt')
            print('APROVADO: 8895 entrega bidirecional sensor02/bridge; sensor01 e publicacao cruzada bloqueados.')
        with p3.broker(rollback, 8896):
            demand(p3.mqtt_delivery(old_lab, old_bridge,'lab/alerts'), 'rollback: alerta nao entregue')
            demand(p3.mqtt_delivery(old_bridge, old_lab,'bus/alerts'), 'rollback: retorno de alerta nao entregue')
            print('APROVADO: 8896 autenticacao legada e alertas bidirecionais recuperados.')
    p2.verify(snapshot, plugin)
    p3.assert_origins_match(snapshot, project, private)
    demand(p3.probe_original() == orig and p3.available(8895) and p3.available(8896),
           'listeners originais alterados ou porta temporaria ocupada')
    report(gaps)
    print('APROVADO: ensaio isolado encerrado, originais preservados, portas 8895/8896 liberadas.')


def mqtt5_puback_denied(options: Path, topic: str, port: int, ca: Path) -> None:
    """Verify explicit MQTT v5 PUBACK reason 0x87; negative must not be a TLS/network failure."""
    demand(port == 8895, 'porta de verificacao MQTT indevida')
    # Options were previously parsed and rewritten by phase53, so read via bounded secure function.
    body = p2.check_regular(options, private=True).decode('utf-8')
    d = dict(line.split(' ',1) for line in body.splitlines())
    demand(d.get('-p') == str(port) and d.get('-u') == 'device-sensor02' and
           d.get('-i') == 'lab84-sensor02' and d.get('--cafile') == str(ca),
           'identidade do teste de negacao invalida')
    def field(value: str) -> bytes:
        buf = value.encode('utf-8')
        demand(len(buf) < 65536, 'campo MQTT excede limite')
        return len(buf).to_bytes(2,'big')+buf
    def length(value: int) -> bytes:
        out = bytearray()
        while True:
            item = value % 128
            value //= 128
            if value:
                item |= 0x80
            out.append(item)
            if not value:
                return bytes(out)
    def read(sock: ssl.SSLSocket) -> tuple[int,bytes]:
        def exact(count: int) -> bytes:
            result=b''
            while len(result)<count:
                part=sock.recv(count-len(result))
                demand(bool(part),'MQTT: conexao encerrada, sem resposta explicita')
                result+=part
            return result
        first=exact(1)[0]
        total=0; mul=1
        for _ in range(4):
            v=exact(1)[0]
            total+=(v & 0x7f)*mul
            if not v & 0x80:
                break
            mul*=128
        else:
            raise Block('MQTT: remaining length invalido')
        demand(total < 8192, 'MQTT: pacote inesperado')
        return first,exact(total)
    context=ssl.create_default_context(cafile=str(ca))
    with socket.create_connection((HOST,port),timeout=4) as raw:
        with context.wrap_socket(raw,server_hostname='localhost') as conn:
            conn.settimeout(4)
            connect=field('MQTT')+b'\x05\xc2\x00\x1e\x00'+field(d['-i'])+field(d['-u'])+field(d['-P'])
            conn.sendall(b'\x10'+length(len(connect))+connect)
            kind, reply=read(conn)
            demand(kind == 0x20 and len(reply)>=3 and reply[1]==0,
                   'MQTT: sessao de controle nao autenticou; negacao inconclusiva')
            message=field(topic)+b'\x00\x01\x00'+b'fase8454-negado'
            conn.sendall(b'\x32'+length(len(message))+message)
            kind, ack=read(conn)
            demand(kind==0x40 and len(ack)>=3 and ack[:2]==b'\x00\x01' and ack[2]==0x87,
                   'MQTT: PUBACK nao confirmou Not Authorized (0x87)')


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('preflight','ensaiar'))
    parser.add_argument('--snapshot',type=Path,required=True)
    parser.add_argument('--project-root',type=Path,default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root',type=Path,default=Path.home()/'.config/rust-server')
    parser.add_argument('--backups-root',type=Path,default=Path.home()/'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path',type=Path,default=p2.PLUGIN)
    args=parser.parse_args()
    try:
        snap,dest,project,private,plugin=(x.absolute() for x in (args.snapshot,args.backups_root,args.project_root,args.private_root,args.plugin_path))
        if args.action=='preflight':
            report(cli_preflight(snap,dest,project,private,plugin))
        else:
            run_lab(snap,dest,project,private,plugin)
        return 0
    except (Block,p2.Block,p3.Block) as err:
        print(f'BLOQUEIO: {err}. Nenhum corte autorizado.',file=sys.stderr)
        return 2
    except (OSError,ValueError,UnicodeError,subprocess.TimeoutExpired,ssl.SSLError):
        print('BLOQUEIO: falha operacional/TLS; detalhes privados nao exibidos. Nenhum corte autorizado.',file=sys.stderr)
        return 2

if __name__=='__main__':
    sys.exit(main())
