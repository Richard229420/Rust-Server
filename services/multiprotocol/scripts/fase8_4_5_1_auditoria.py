#!/usr/bin/env python3
"""Fase 8.4.5.1: inventario de migracao MQTT SOMENTE LEITURA.

Nenhuma escrita, conexao MQTT, execucao de controle DynSec ou reinicio de processos.
Relatorio publico com mensagens fixas: nunca exibe senhas, hashes ou JSON bruto.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

LIMIT = 8 * 1024 * 1024
DEVICE_ID = re.compile(r'[a-z][a-z0-9-]{2,31}\Z')
PLUGIN_DEFAULT = Path('/usr/lib/mosquitto_dynamic_security.so')
ALLOWED_STAGES = {'prepared', 'rotation-requested', 'rotation-verified', 'disable-requested', 'completed'}
LEGACY_BASE = {
    'bridge': {
        'read lab/alerts', 'read lab/sensors/#',
        'write bus/alerts', 'write bus/sensors/#',
    },
    'lab': {'write lab/alerts', 'read bus/alerts'},
}


class Invalid(Exception):
    """Generic failure. Do not include sensitive input data in output."""


def read_checked(path: Path, private: bool, *, base: Path) -> bytes:
    """Bounded, no symlinks, no hardlinks, owner+mode checks; no plaintext printed."""
    try:
        if not path.is_relative_to(base) or path == base:
            raise Invalid()
        for parent in (path, *path.parents):
            if parent == base.parent:
                break
            if parent.is_symlink():
                raise Invalid()
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
            raise Invalid()
        if st.st_nlink != 1 or st.st_size > LIMIT or st.st_size < 1:
            raise Invalid()
        if private and st.st_mode & 0o077:
            raise Invalid()
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            opened = os.fstat(fd)
            if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                    (st.st_dev, st.st_ino, st.st_size)):
                raise Invalid()
            if opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode):
                raise Invalid()
            if private and opened.st_mode & 0o077:
                raise Invalid()
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                data = stream.read(LIMIT + 1)
            if len(data) != st.st_size:
                raise Invalid()
            return data
        except (OSError, UnicodeError):
            raise Invalid() from None
        finally:
            os.close(fd)
    except (OSError, ValueError):
        raise Invalid() from None



def metadata_checked(path: Path, private: bool, *, base: Path) -> bool:
    """Check ownership/type/mode without reading sensitive file bytes."""
    try:
        if not path.is_relative_to(base) or path == base:
            return False
        for parent in (path, *path.parents):
            if parent == base.parent:
                break
            if parent.is_symlink():
                return False
        st = path.lstat()
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
            return False
        if not (0 < st.st_size <= LIMIT) or st.st_nlink != 1:
            return False
        if private and (st.st_mode & 0o077):
            return False
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        try:
            actual = os.fstat(fd)
            return ((actual.st_dev, actual.st_ino, actual.st_size) ==
                    (st.st_dev, st.st_ino, st.st_size) and
                    stat.S_ISREG(actual.st_mode) and actual.st_nlink == 1 and
                    (not private or not (actual.st_mode & 0o077)))
        finally:
            os.close(fd)
    except (OSError, ValueError):
        return False


def private_dir(path: Path, *, base: Path) -> bool:
    try:
        if not path.is_relative_to(base) or path.is_symlink():
            return False
        s = path.stat()
        return stat.S_ISDIR(s.st_mode) and s.st_uid == os.geteuid() and not s.st_mode & 0o077
    except OSError:
        return False


def directives(data: bytes) -> dict[str, list[tuple[str, ...]]]:
    try:
        text = data.decode('utf-8')
    except UnicodeError:
        raise Invalid() from None
    out: dict[str, list[tuple[str, ...]]] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if not parts or len(parts[0]) > 80:
            raise Invalid()
        out.setdefault(parts[0], []).append(tuple(parts[1:]))
    return out


def exact_one(cfg: dict[str, list[tuple[str, ...]]], key: str, expected: tuple[str, ...]) -> bool:
    return cfg.get(key) == [expected]


def verify_inventory(data: bytes) -> dict[str, str]:
    try:
        state = json.loads(data)
        if state.get('version') != 1 or not isinstance(state.get('devices'), dict):
            raise Invalid()
        d = state['devices']
        if not d or len(d) > 32:
            raise Invalid()
        for key, value in d.items():
            if not isinstance(key, str) or not DEVICE_ID.fullmatch(key) or '--' in key or key.endswith('-'):
                raise Invalid()
            if not isinstance(value, dict) or value.get('state') not in ('active', 'revoked'):
                raise Invalid()
        return {name: info['state'] for name, info in d.items()}
    except (ValueError, TypeError, AttributeError):
        raise Invalid() from None


def usernames(data: bytes) -> set[str]:
    try:
        text = data.decode('utf-8')
        users = []
        for raw in text.splitlines():
            if not raw.strip():
                continue
            user, sep, hash_value = raw.partition(':')
            if not sep or not hash_value.startswith('$') or not user or len(user) > 64:
                raise Invalid()
            users.append(user)
        if len(set(users)) != len(users) or not users:
            raise Invalid()
        return set(users)
    except UnicodeError:
        raise Invalid() from None


def acl_rules(data: bytes) -> dict[str, set[str]]:
    try:
        text = data.decode('utf-8')
        out: dict[str, set[str]] = {}
        current = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) == 2 and parts[0] == 'user':
                if parts[1] in out:
                    raise Invalid()
                current = parts[1]
                out[current] = set()
            elif len(parts) == 3 and parts[0] == 'topic' and current:
                if parts[1] not in ('read', 'write'):
                    raise Invalid()
                rule = f'{parts[1]} {parts[2]}'
                if rule in out[current]:
                    raise Invalid()
                out[current].add(rule)
            else:
                raise Invalid()
        if not out:
            raise Invalid()
        return out
    except UnicodeError:
        raise Invalid() from None


def compare_acl(rules: dict[str, set[str]], inventory: dict[str, str]) -> bool:
    expected = {key: set(value) for key, value in LEGACY_BASE.items()}
    for device, state in inventory.items():
        if state == 'active':
            expected[f'device-{device}'] = {
                f'write lab/sensors/{device}/#',
                f'read bus/sensors/{device}/#',
            }
    return rules == expected


def probe_listeners() -> tuple[str, str]:
    """Read-only kernel socket listing. Never connect to either broker."""
    try:
        res = subprocess.run(['ss', '-H', '-lnt'], capture_output=True, text=True,
                             timeout=5, check=False)
        if res.returncode != 0:
            return ('desconhecido', 'desconhecido')
        names = []
        for port in (8883, 8884):
            listeners = []
            for line in res.stdout.splitlines():
                cols = line.split()
                if len(cols) < 4:
                    continue
                local = cols[3]
                if local.endswith(f':{port}'):
                    listeners.append(local)
            if not listeners:
                names.append('parado')
            elif listeners == [f'127.0.0.1:{port}']:
                names.append('loopback')
            else:
                names.append('exposto-ou-inesperado')
        return tuple(names)
    except (OSError, subprocess.TimeoutExpired):
        return ('desconhecido', 'desconhecido')


class Report:
    def __init__(self):
        self.blockers = 0
        self.pending = 0

    def status(self, name: str, ok: bool) -> None:
        print(f'{"APROVADO" if ok else "BLOQUEIO"}: {name}')
        if not ok:
            self.blockers += 1

    def pending_manual(self, name: str) -> None:
        print(f'PENDENTE: {name}')
        self.pending += 1


def read_or_none(path: Path, *, private: bool, base: Path) -> bytes | None:
    try:
        return read_checked(path, private, base=base)
    except Invalid:
        return None


def audit(project: Path, root: Path, plugin: Path, runtime: bool = True) -> int:
    lab = root / 'phase8-4-2-lab'
    mosq = root / 'mosquitto'
    report = Report()
    print('=== RUST-SERVER FASE 8.4.5.1: AUDITORIA SOMENTE LEITURA ===')
    print('Escopo: 8883 legado e 8884 laboratorio, sem alteracoes nem exibicao de segredos.')
    report.status('diretorios privados do projeto MQTT (root, mosquitto, lab, pki e clients)',
                  all(private_dir(path, base=root) for path in
                      (root, mosq, lab, lab / 'pki', lab / 'clients')))

    # Legacy config: all values are compared in memory but never printed.
    conf = read_or_none(mosq / 'mosquitto.conf', private=True, base=root)
    cfg = None
    if conf is not None:
        try:
            cfg = directives(conf)
        except Invalid:
            pass
    report.status('configuracao legada privada e legivel', cfg is not None)
    if cfg is not None:
        expected = {
            'listener': ('8883', '127.0.0.1'),
            'allow_anonymous': ('false',),
            'password_file': (str(mosq / 'passwords'),),
            'acl_file': (str(mosq / 'acl'),),
            'certfile': (str(project / 'certs/localhost.crt'),),
            'keyfile': (str(project / 'certs/localhost.key'),),
        }
        check_cfg = all(exact_one(cfg, key, value) for key, value in expected.items())
        dangerous = {'plugin', 'global_plugin', 'plugin_load', 'plugin_use',
                     'include_dir', 'listener_allow_anonymous', 'auth_plugin',
                     'per_listener_settings', 'require_certificate'}
        check_cfg = check_cfg and not any(key in cfg for key in dangerous)
        report.status('8883: unico listener loopback, ACL/password legados e TLS separados', check_cfg)
        report.status('8883: TLS minimo 1.2 e persistencia desativada',
                      exact_one(cfg, 'tls_version', ('tlsv1.2',)) and
                      exact_one(cfg, 'persistence', ('false',)))

    inventory_bytes = read_or_none(mosq / 'devices.json', private=True, base=root)
    inventory = None
    if inventory_bytes is not None:
        try:
            inventory = verify_inventory(inventory_bytes)
        except Invalid:
            pass
    report.status('inventario 8.3 integro (sem publicar metadados privados)', inventory is not None)
    if inventory is not None:
        report.status('sensor01 revogado e sensor02 ativo no inventario legado',
                      inventory.get('sensor01') == 'revoked' and inventory.get('sensor02') == 'active')
        print(f'INFO: dispositivos no inventario 8883: {len(inventory)}; '
              f'ativos={sum(s == "active" for s in inventory.values())}; '
              f'revogados={sum(s == "revoked" for s in inventory.values())}.')

    passwords = read_or_none(mosq / 'passwords', private=True, base=root)
    users = None
    if passwords is not None:
        try:
            users = usernames(passwords)
        except Invalid:
            pass
    report.status('password_file privado, somente hashes em formato esperado', users is not None)
    if users is not None and inventory is not None:
        expected_users = {'bridge', 'lab'} | {f'device-{name}' for name, state in inventory.items()
                                              if state == 'active'}
        report.status('contas: inventario, senhas e revogacoes coerentes', users == expected_users)
        print(f'INFO: contas no password_file 8883: {len(users)} (nomes e hashes omitidos).')

    acl_bytes = read_or_none(mosq / 'acl', private=True, base=root)
    acl = None
    if acl_bytes is not None:
        try:
            acl = acl_rules(acl_bytes)
        except Invalid:
            pass
    report.status('ACL legado sintaticamente restrito (sem patterns ou curinga global)', acl is not None)
    if acl is not None and inventory is not None:
        report.status('ACL 8883: permissoes minimas e dispositivo revogado excluido',
                      compare_acl(acl, inventory))

    for name in ('certs/ca.crt', 'certs/localhost.crt', 'certs/localhost.key'):
        report.status(f'8883: material TLS {name} presente, seguro e legivel',
                      metadata_checked(project / name, private=name.endswith('.key'), base=project))

    # Dynamic security lab. We intentionally do NOT open dynamic-security.json or *.opts.
    lab_config_bytes = read_or_none(lab / 'mosquitto-lab.conf', private=True, base=root)
    lab_cfg = None
    if lab_config_bytes is not None:
        try:
            lab_cfg = directives(lab_config_bytes)
        except Invalid:
            pass
    report.status('8884: configuracao privada e legivel', lab_cfg is not None)
    if lab_cfg is not None:
        expected_lab = {
            'listener': ('8884', '127.0.0.1'),
            'listener_allow_anonymous': ('false',),
            'plugin_load': ('labdynsec', str(plugin)),
            'plugin_use': ('labdynsec',),
            'plugin_opt_config_file': (str(lab / 'dynamic-security.json'),),
            'certfile': (str(lab / 'pki/server.crt'),),
            'keyfile': (str(lab / 'pki/server.key'),),
            'cafile': (str(lab / 'pki/ca.crt'),),
        }
        valid_lab = all(exact_one(lab_cfg, k, v) for k, v in expected_lab.items())
        valid_lab = valid_lab and not any(k in lab_cfg for k in ('allow_anonymous', 'password_file',
                                        'acl_file', 'plugin', 'global_plugin', 'include_dir'))
        report.status('8884: DynSec no listener loopback e anonimato negado', valid_lab)
    try:
        pstat = plugin.lstat()
        plugin_ok = stat.S_ISREG(pstat.st_mode) and not plugin.is_symlink()
    except OSError:
        plugin_ok = False
    report.status('plugin Dynamic Security instalado no caminho previsto', plugin_ok)
    report.status('estado DynSec privado presente (conteudo e hashes nao lidos)',
                  metadata_checked(lab / 'dynamic-security.json', private=True, base=root))
    opts = ('device-sensor01.opts', 'device-sensor02.opts', 'lab84-bridge.opts')
    # Only check stat for credentials, never read their contents.
    opts_ok = all(metadata_checked(lab / 'clients' / name, private=True, base=root) for name in opts)
    report.status('arquivos .opts de sensores e bridge privados (nao lidos)', opts_ok)
    for name in ('pki/ca.crt', 'pki/server.crt', 'pki/server.key'):
        report.status(f'8884: material TLS {name} presente, seguro e legivel',
                      metadata_checked(lab / name, private=name.endswith('.key'), base=root))

    marker = read_or_none(lab / 'fase8_4_4_state.json', private=True, base=root)
    stage_ok = False
    if marker is not None:
        try:
            state = json.loads(marker)
            stage_ok = (state.get('phase') == '8.4.4' and state.get('stage') == 'completed' and
                        state.get('target') == 'device-sensor01' and state.get('port') == 8884)
        except (ValueError, TypeError, AttributeError):
            pass
    report.status('marco privado 8.4.4 concluido (nao substitui autenticacao real)', stage_ok)

    if runtime:
        one, two = probe_listeners()
        report.status('8883: listener em loopback, sem exposicao publica',
                      one != 'exposto-ou-inesperado')
        report.status('8884: listener em loopback, sem exposicao publica',
                      two != 'exposto-ou-inesperado')
        print(f'INFO: portas: 8883={one}; 8884={two} (consulta passiva, sem conexao).')

    report.pending_manual('paridade DynSec de usuarios/grupos/papeis e ACL em memoria: fase 8.4.5.4')
    report.pending_manual('evidencias de backup/rollback operacional e aprovacao de corte: fases 8.4.5.2-8.4.5.5')
    report.pending_manual('certificados: validade, SAN e verificacao criptografica ponta a ponta na fase 8.4.5.4')
    print(f'RESUMO: bloqueios={report.blockers}; verificacoes futuras={report.pending}.')
    print('NENHUMA alteracao em certificados, contas, processos ou arquivos de configuracao.')
    if report.blockers:
        print('RESULTADO: REPROVADO PARA PREPARAR MIGRACAO; corrigir bloqueios sem mudar o 8883.')
        return 2
    print('RESULTADO: APROVADO PARA PREPARACAO DA 8.4.5.2; MIGRACAO REAL NAO AUTORIZADA.')
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--plugin-path', type=Path, default=PLUGIN_DEFAULT)
    parser.add_argument('--no-runtime', action='store_true', help='sem consulta passiva ss (testes offline)')
    a = parser.parse_args()
    if os.geteuid() == 0:
        print('BLOQUEIO: execute como usuario comum; sudo/root proibido.')
        return 2
    try:
        return audit(a.project_root.absolute(), a.private_root.absolute(), a.plugin_path.absolute(), not a.no_runtime)
    except (Invalid, OSError, ValueError):
        print('BLOQUEIO: nao foi possivel validar a estrutura sem risco; nao imprimir dados brutos.')
        return 2


if __name__ == '__main__':
    sys.exit(main())
