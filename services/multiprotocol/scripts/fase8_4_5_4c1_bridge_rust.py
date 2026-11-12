#!/usr/bin/env python3
"""8.4.5.4-C.1: bridge.rs Rust REAL contra broker DynSec descartavel 8895.

Nao executa servidor principal, nao modifica 8883/8884/snapshot, nao toca
credenciais reais; reutiliza somente politica legada do snapshot (read-only).
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import queue
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time

import fase8_4_5_2_preparar as p2
import fase8_4_5_3_ensaio as p3
import fase8_4_5_4_paridade as p4
import fase8_4_5_4b_paridade_producao as p4b

HOST = '127.0.0.1'
PORT = 8895
BRIDGE_CLIENT_ID = 'rust-server-bridge-local'
PROBE_SOURCE = 'fase8_4_5_4c1_bridge_probe.rs'
PROBE_NAME = 'phase8454c1_probe'
IDS = {**p4b.IDS, 'bridge': BRIDGE_CLIENT_ID}

class Block(Exception):
    """Mensagem fixa e livre de informacoes privadas."""


def need(ok: bool, message: str) -> None:
    if not ok:
        raise Block(message)


def check_source(project: Path) -> None:
    # Reusar a IMPLEMENTACAO real; nao criar uma nova bridge ou relaxar mqtt.rs.
    source = p2.check_regular(project / 'src/bridge.rs', private=False)
    need(b'MqttOptions::new("rust-server-bridge-local", "localhost", broker.port())' in source,
         'Client ID da bridge Rust divergiu; rever codigo antes do ensaio')
    need(b'options.set_credentials("bridge", password)' in source and
         b'options.set_transport(Transport::tls_with_config(client_tls.into()))' in source and
         b'pub fn start(' in source and b'bus.publish_from_mqtt(' in source,
         'autenticacao TLS/bridge Rust nao corresponde ao baseline')
    # Nao aceitar substituicao arbitraria do proprio probe por symlink.
    probe = project / 'scripts' / PROBE_SOURCE
    need(probe.is_file() and not probe.is_symlink(), 'probe Rust ausente ou symlink')


def listener_absent(port: int) -> bool:
    """Porta sem LISTEN; TIME_WAIT nao prova que um broker segue ativo.

    Consulta passiva, sem interagir com processos alheios nem usar bind().
    O encerramento do broker C.1 tambem exige wait() no PID que criamos.
    """
    need(port in (PORT, 8896), 'porta fora do escopo do ensaio')
    try:
        result = subprocess.run(['ss', '-H', '-lnt'], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=4, check=False, text=True)
    except (OSError, subprocess.TimeoutExpired):
        raise Block('consulta passiva da porta temporaria indisponivel') from None
    need(result.returncode == 0, 'consulta passiva da porta temporaria falhou')
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].rsplit(':', 1)[-1] == str(port):
            return False
    return True


@contextmanager
def broker_for_bridge(config: Path, port: int):
    """Broker descartavel C.1: verifica fim do PID e ausencia de listener.

    Isolado da verificacao bind() usada nas demais fases; essas nao mudam.
    """
    need(port == PORT and p3.available(port) and listener_absent(port),
         'porta temporaria ocupada antes do ensaio')
    proc = None
    try:
        proc = subprocess.Popen(['mosquitto', '-c', str(config)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, start_new_session=False)
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline:
            need(proc.poll() is None, 'broker descartavel encerrou antes de iniciar')
            if p3.port_alive(port):
                break
            time.sleep(0.1)
        else:
            raise Block('broker descartavel nao abriu o listener')
        yield
    finally:
        if proc is not None:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()  # Nunca sinalizar processos externos.
                    proc.wait(timeout=4)
            else:
                proc.wait(timeout=4)  # Recolhe apenas o filho do proprio ensaio.
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline and not listener_absent(port):
                time.sleep(0.1)
            need(listener_absent(port), 'broker descartavel terminou mas listener permanece')


def preflight(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path):
    mapping = p4b.preflight(snapshot, backups, project, private, plugin)
    check_source(project)
    need(shutil.which('cargo') is not None, 'cargo nao instalado')
    need(p3.available(PORT) and p3.available(8896), 'porta temporaria ocupada')
    return mapping


def private_file(path: Path, content: bytes) -> Path:
    p2.write_exclusive(path, content)
    need((path.stat().st_mode & 0o777) == 0o600, 'arquivo nao privado')
    return path


def restricted_env() -> dict[str, str]:
    """Do not pass Rust-Server secrets, cloud credentials or arbitrary env into probes."""
    allowed = {'PATH', 'HOME', 'USER', 'LOGNAME', 'LANG', 'LC_ALL',
               'RUSTUP_HOME', 'CARGO_HOME', 'TMPDIR'}
    return {key: value for key, value in os.environ.items() if key in allowed}


def build_probe(scratch: Path, project: Path) -> Path:
    """Build isolado: Cargo.lock, target e codigo-fonte ficam FORA do Git."""
    p2.mkdirs_locked(scratch, PurePosixPath('rust-probe/src'))
    folder = scratch / 'rust-probe'
    cargo = ('[package]\nname = "phase8454c1_probe"\nversion = "0.1.0"\n'
             'edition = "2021"\n\n[dependencies]\n'
             'rumqttc = { version = "=0.25.1", default-features = false, '
             'features = ["use-rustls"] }\n'
             'rustls-pemfile = "2.2"\n'
             'rustls = { version = "0.23", default-features = false, '
             'features = ["ring"] }\n')
    private_file(folder / 'Cargo.toml', cargo.encode())
    for source, target in (
        (project / 'src/bridge.rs', folder / 'src/bridge.rs'),
        (project / 'scripts' / PROBE_SOURCE, folder / 'src/main.rs'),
    ):
        private_file(target, p2.check_regular(source, private=False))
    try:
        proc = subprocess.run(['cargo', 'build', '--offline', '--quiet', '--manifest-path',
                               str(folder / 'Cargo.toml')], cwd=folder,
                              env={**restricted_env(), 'CARGO_TARGET_DIR': str(folder / 'target'),
                                   'CARGO_INCREMENTAL': '0', 'CARGO_NET_OFFLINE': 'true'},
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Block('compilacao isolada do probe Rust indisponivel') from None
    need(proc.returncode == 0, 'compilacao do probe Rust falhou (veja diagnostico local documentado)')
    executable = folder / 'target/debug' / PROBE_NAME
    need(executable.is_file() and not executable.is_symlink(), 'executavel Rust nao foi gerado')
    return executable


def verify_candidate(state: Path, mapping: dict) -> None:
    try:
        data = json.loads(p2.check_regular(state, private=True))
    except (ValueError, UnicodeError):
        raise Block('estado DynSec descartavel invalido') from None
    need(isinstance(data, dict) and isinstance(data.get('defaultACLAccess'), dict) and
         all(data['defaultACLAccess'].get(k) is False for k in p4b.DEFAULTS),
         'DEFAULT DENY incompleto')
    clients = p4.unique_by(data.get('clients'), 'username')
    roles = p4.unique_by(data.get('roles'), 'rolename')
    need(set(clients) == set(p4b.ACCOUNTS) | {p4b.ADMIN}, 'contas inesperadas')
    for user in p4b.ACCOUNTS:
        entry = clients[user]
        need(entry.get('clientid', entry.get('clientId')) == IDS[user] and
             entry.get('disabled', False) is False and
             p4.reference_names(entry.get('roles'), 'rolename') == {p4b.role_name(user)} and
             not p4.reference_names(entry.get('groups'), 'groupname'),
             'identidade nao corresponde a politica isolada')
        role = roles.get(p4b.role_name(user))
        need(role is not None and isinstance(role.get('acls'), list), 'role candidata ausente')
        found = set()
        for acl in role['acls']:
            need(isinstance(acl, dict) and acl.get('allow') is True and
                 isinstance(acl.get('topic'), str) and isinstance(acl.get('acltype'), str),
                 'ACL malformada ou permissao deny inesperada')
            found.add((acl['acltype'], acl['topic']))
        need(len(found) == len(role['acls']) and found == set(mapping[user]),
             'ACL candidata nao equivalente ao legado')


def dyn_change(admin_opts: Path, operation: str, *, password: str | None = None) -> None:
    need(operation in ('disableClient', 'enableClient', 'setClientPassword'),
         'operacao administrativa nao permitida')
    need(password is None if operation != 'setClientPassword' else
         password is not None and len(password) == 64 and password.isalnum(),
         'senha invalida para rotacao')
    p4b.call(['mosquitto_ctrl', '-o', str(admin_opts), 'dynsec', operation, 'bridge'],
             input_text=None if password is None else f'{password}\n{password}\n', timeout=15)


class RustProbe:
    def __init__(self, executable: Path, ca: Path, password_file: Path):
        self.proc = subprocess.Popen([str(executable), str(ca), str(password_file)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, text=True, bufsize=1,
                                     env=restricted_env())
        self.stdout: queue.Queue[str] = queue.Queue()
        self.connections: queue.Queue[str] = queue.Queue()
        def output():
            assert self.proc.stdout is not None
            for line in self.proc.stdout:
                if line.startswith(('READY', 'IN ', 'QUEUED ')):
                    self.stdout.put(line.rstrip('\n'))
        def errors():
            assert self.proc.stderr is not None
            for line in self.proc.stderr:
                if '[BRIDGE] MQTT conectado em 127.0.0.1:8895' in line:
                    self.connections.put('CONNECTED')
        threading.Thread(target=output, daemon=True).start()
        threading.Thread(target=errors, daemon=True).start()
        try:
            self.wait_output('READY', 8)
        except BaseException:
            # A failure while constructing the worker must never orphan the process.
            if self.proc.poll() is None:
                self.proc.kill()
            self.proc.wait(timeout=4)
            for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
                if stream: stream.close()
            raise

    def wait_output(self, prefix: str, timeout: float) -> str:
        stop = time.monotonic() + timeout
        while time.monotonic() < stop:
            need(self.proc.poll() is None, 'probe Rust encerrou inesperadamente')
            try:
                line = self.stdout.get(timeout=min(0.25, max(0.01, stop-time.monotonic())))
            except queue.Empty:
                continue
            if line == prefix or line.startswith(prefix):
                return line
        raise Block('probe Rust nao comprovou evento esperado')

    def connected(self, timeout: float = 12):
        need(self.proc.poll() is None, 'probe Rust terminou durante reconexao')
        try:
            need(self.connections.get(timeout=timeout) == 'CONNECTED',
                 'CONNACK Rust nao confirmado')
        except queue.Empty:
            raise Block('CONNACK ou reconexao da bridge Rust nao confirmado') from None

    def publish_bus(self, marker: str):
        need(marker.startswith('c1-') and marker.replace('-', '').isalnum(),
             'payload inesperado')
        need(self.proc.stdin is not None, 'stdin indisponivel')
        self.proc.stdin.write(f'PUB {marker}\n')
        self.proc.stdin.flush()
        need(self.wait_output(f'QUEUED {marker}', 3) == f'QUEUED {marker}',
             'Bus nao enfileirou')

    def close(self):
        if self.proc.poll() is None:
            try:
                assert self.proc.stdin is not None
                self.proc.stdin.write('STOP\n'); self.proc.stdin.flush()
                self.proc.wait(timeout=3)
            except (OSError, subprocess.TimeoutExpired):
                self.proc.terminate()
                try: self.proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.proc.kill(); self.proc.wait(timeout=3)
        for stream in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            if stream: stream.close()
        need(self.proc.returncode == 0, 'probe Rust nao encerrou corretamente')


@contextmanager
def probe(executable: Path, ca: Path, scratch: Path, pw: str):
    token = private_file(scratch / 'bridge-probe-password', pw.encode('ascii'))
    worker = None
    try:
        worker = RustProbe(executable, ca, token)
        yield worker
    finally:
        if worker is not None: worker.close()
        token.unlink(missing_ok=True)


def mqtt_to_rust(worker: RustProbe, opts: Path):
    marker = 'c1-in-' + secrets.token_hex(5)
    for attempt in range(3):
        need(p3.safe_run(['mosquitto_pub', '-o', str(opts), '-t', 'lab/alerts',
                          '-q', '1', '-m', marker], timeout=7),
             'publicacao de lab rejeitada')
        try:
            need(worker.wait_output('IN alerts ' + marker, 2.5) == 'IN alerts ' + marker,
                 'encaminhamento MQTT para Bus diferente do esperado')
            return
        except Block:
            if attempt == 2: raise Block('MQTT->bridge.rs nao entregue') from None


def rust_to_mqtt(worker: RustProbe, options: Path):
    marker = 'c1-out-' + secrets.token_hex(5)
    receiver = None
    try:
        receiver = subprocess.Popen(['mosquitto_sub', '-o', str(options), '-t', 'bus/alerts',
                                     '-C', '1', '-W', '7', '-R'],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    stdin=subprocess.DEVNULL)
        time.sleep(0.65)
        need(receiver.poll() is None, 'assinatura do cliente lab rejeitada')
        worker.publish_bus(marker)
        result, _ = receiver.communicate(timeout=9)
        need(receiver.returncode == 0 and result.strip() == marker.encode('ascii'),
             'bridge.rs->MQTT bus/alerts nao entregue')
    except subprocess.TimeoutExpired:
        raise Block('entrega bus->MQTT expirou') from None
    finally:
        if receiver is not None:
            if receiver.poll() is None:
                receiver.terminate()
                try: receiver.wait(timeout=2)
                except subprocess.TimeoutExpired: receiver.kill(); receiver.wait(timeout=2)
            if receiver.stdout: receiver.stdout.close()


def exercise(worker: RustProbe, lab_opts: Path):
    worker.connected()
    mqtt_to_rust(worker, lab_opts)
    rust_to_mqtt(worker, lab_opts)


def run(snapshot: Path, backups: Path, project: Path, private: Path, plugin: Path):
    mapping = preflight(snapshot, backups, project, private, plugin)
    before = p3.probe_original()
    with tempfile.TemporaryDirectory(prefix='.rust-bridge-8454c1-', dir=backups) as temp:
        scratch = Path(temp); os.chmod(scratch, 0o700)
        p3.restore_files(snapshot, scratch)
        executable = build_probe(scratch, project)
        p2.mkdirs_locked(scratch, PurePosixPath('production-candidate'))
        admin_pw = secrets.token_hex(32)
        state = scratch / 'production-candidate/dynamic-security.json'
        p4b.init_dynsec(scratch, state, admin_pw)
        config = p4b.config(scratch, plugin)
        p3.config_check(config)
        ca = scratch / 'files/legacy/certs/ca.crt'
        admin_opts = p3.options_file(scratch, 'c1-admin',
            p4b.opts(ca, p4b.ADMIN, admin_pw, 'phase8454c1-admin'))
        passwords = {user: secrets.token_hex(32) for user in p4b.ACCOUNTS}
        lab_opts = p3.options_file(scratch, 'c1-lab',
            p4b.opts(ca, 'lab', passwords['lab'], IDS['lab']))
        with broker_for_bridge(config, PORT):
            for category in p4b.DEFAULTS:
                p4b.control(admin_opts, 'setDefaultACLAccess', category, 'deny')
            for user in p4b.ACCOUNTS:
                role = p4b.role_name(user)
                p4b.control(admin_opts, 'createRole', role)
                for acltype, topic in mapping[user]:
                    p4b.control(admin_opts, 'addRoleACL', role, acltype, topic, 'allow', '10')
                pw = passwords[user]
                p4b.control(admin_opts, 'createClient', user, input_text=pw + '\n' + pw + '\n')
                p4b.control(admin_opts, 'setClientId', user, IDS[user])
                p4b.control(admin_opts, 'addClientRole', user, role, '10')
            verify_candidate(state, mapping)
            p4b.mqtt5_check(ca, 'device-sensor01', secrets.token_hex(32),
                            'phase8454c1-revoked', expect_auth=False)
            print('APROVADO: DynSec descartavel DEFAULT DENY e bridge vinculada ao Client ID Rust; sensor01 bloqueado.')
            with probe(executable, ca, scratch, passwords['bridge']) as worker:
                exercise(worker, lab_opts)
                print('APROVADO: bridge.rs real com TLS, CONNACK, MQTT->bus e bus->MQTT no 8895.')
                dyn_change(admin_opts, 'disableClient')
                dyn_change(admin_opts, 'enableClient')
                worker.connected(timeout=18)
                mqtt_to_rust(worker, lab_opts)
                rust_to_mqtt(worker, lab_opts)
                print('APROVADO: bridge Rust reconectou apos disable/enable do candidato, sem reinicio do probe.')
            # Senha ALTERADA enquanto bridge Rust esta parada; sem reusar credenciais existentes.
            new_pw = secrets.token_hex(32)
            dyn_change(admin_opts, 'setClientPassword', password=new_pw)
            p4b.mqtt5_check(ca, 'bridge', passwords['bridge'], BRIDGE_CLIENT_ID, expect_auth=False)
            with probe(executable, ca, scratch, new_pw) as worker:
                exercise(worker, lab_opts)
            print('APROVADO: senha antiga negada, nova credencial aceita apos recriar processo da bridge.')
            dyn_change(admin_opts, 'setClientPassword', password=passwords['bridge'])
            p4b.mqtt5_check(ca, 'bridge', new_pw, BRIDGE_CLIENT_ID, expect_auth=False)
            with probe(executable, ca, scratch, passwords['bridge']) as worker:
                exercise(worker, lab_opts)
            print('APROVADO: retorno a credencial temporaria anterior e reconexao com entrega bidirecional.')
        # Broker e Rust parados antes de apagar scratch; NUNCA restaura arquivos na origem.
    p2.verify(snapshot, plugin)
    p3.assert_origins_match(snapshot, project, private)
    need(p3.probe_original() == before and listener_absent(PORT) and listener_absent(8896),
         'estado de brokers originais ou listeners temporarios divergiu')
    print('APROVADO: originais 8883/8884, snapshot e codigo Rust intactos; 8895 sem listener; scratch removido.')
    print('PENDENTE: prova de clientes reais lab/sensor02, rotação operacional real, Git/CI e Seguranca.')
    print('RESULTADO: C.1 ENSAIO ISOLADO APROVADO; CORTE 8883 NAO AUTORIZADO.')


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
        snapshot, backups, project, private, plugin = [x.absolute() for x in (
            args.snapshot, args.backups_root, args.project_root, args.private_root, args.plugin_path)]
        if args.action == 'preflight':
            preflight(snapshot, backups, project, private, plugin)
            print('APROVADO: baseline, snapshot, fonte Rust, ferramentas e porta 8895 livres.')
            print('AVISO: cargo --offline compila copia temporaria fora do Git; nao altera src/config.rs ou src/mqtt.rs.')
            print('Corte 8883 NAO AUTORIZADO.')
        else:
            run(snapshot, backups, project, private, plugin)
        return 0
    except (Block, p2.Block, p3.Block, p4.Block, p4b.Block) as err:
        print(f'BLOQUEIO: {err}. Nenhum corte autorizado.', file=sys.stderr)
        return 2
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print('BLOQUEIO: erro operacional do ensaio; detalhes sensiveis omitidos.', file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
