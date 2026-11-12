#!/usr/bin/env python3
"""Testes offline de guarda e controle da fase 8.4.5.4-C.1 (sem brokers)."""
from pathlib import Path
import json
import os
import queue
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
import fase8_4_5_4c1_bridge_rust as mod


class Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'src').mkdir()
        (self.root / 'scripts').mkdir()
        self.brs = self.root / 'src/bridge.rs'
        self.probe = self.root / 'scripts' / mod.PROBE_SOURCE
        self.brs.write_text('''pub fn start( ) {\nlet x = MqttOptions::new("rust-server-bridge-local", "localhost", broker.port());
options.set_credentials("bridge", password);
options.set_transport(Transport::tls_with_config(client_tls.into()));
bus.publish_from_mqtt(topic, body);
}''')
        self.probe.write_text('fn main() {}')

    def test_fonte_valida(self): mod.check_source(self.root)
    def test_fonte_id_mutado(self):
        self.brs.write_text(self.brs.read_text().replace('rust-server-bridge-local', 'falso'))
        with self.assertRaises(mod.Block): mod.check_source(self.root)
    def test_fonte_usuario_mutado(self):
        self.brs.write_text(self.brs.read_text().replace('"bridge", password', '"admin", password'))
        with self.assertRaises(mod.Block): mod.check_source(self.root)
    def test_fonte_tls_removido(self):
        self.brs.write_text(self.brs.read_text().replace('options.set_transport', 'options.nao_tem_tls'))
        with self.assertRaises(mod.Block): mod.check_source(self.root)
    def test_fonte_sem_inbound(self):
        self.brs.write_text(self.brs.read_text().replace('bus.publish_from_mqtt', 'bus.ignora_mqtt'))
        with self.assertRaises(mod.Block): mod.check_source(self.root)
    def test_fonte_probe_ausente(self):
        self.probe.unlink()
        with self.assertRaises(mod.Block): mod.check_source(self.root)
    def test_fonte_probe_symlink(self):
        self.probe.unlink(); self.probe.symlink_to(self.brs)
        with self.assertRaises(mod.Block): mod.check_source(self.root)
    def test_identidade_bridge(self): self.assertEqual(mod.IDS['bridge'], 'rust-server-bridge-local')
    def test_identidades_nao_revogadas(self):
        self.assertEqual(set(mod.IDS), {'lab', 'bridge', 'device-sensor02'})
        self.assertNotIn('device-sensor01', mod.IDS)

    def test_dynsec_acao_nao_permitida(self):
        with self.assertRaises(mod.Block): mod.dyn_change(Path('/tmp/fake'), 'deleteClient')
    def test_dynsec_senha_nao_requerida(self):
        with self.assertRaises(mod.Block): mod.dyn_change(Path('/tmp/fake'), 'enableClient', password='A' * 64)
    def test_dynsec_senha_curta(self):
        with self.assertRaises(mod.Block): mod.dyn_change(Path('/tmp/fake'), 'setClientPassword', password='x')
    def test_dynsec_senha_com_quebra(self):
        with self.assertRaises(mod.Block): mod.dyn_change(Path('/tmp/fake'), 'setClientPassword', password='A' * 63 + '\n')
    def test_dynsec_senha_por_stdin(self):
        with patch.object(mod.p4b, 'call') as called:
            mod.dyn_change(Path('/tmp/seguro.opts'), 'setClientPassword', password='A'*64)
            argv = called.call_args.args[0]
            self.assertNotIn('A'*64, ' '.join(argv))
            self.assertEqual(argv[-2:], ['setClientPassword', 'bridge'])
            self.assertEqual(called.call_args.kwargs['input_text'], 'A'*64+'\n'+'A'*64+'\n')
    def test_dynsec_disable(self):
        with patch.object(mod.p4b, 'call') as called:
            mod.dyn_change(Path('/tmp/seguro.opts'), 'disableClient')
            self.assertIsNone(called.call_args.kwargs['input_text'])
    def test_dynsec_enable(self):
        with patch.object(mod.p4b, 'call') as called:
            mod.dyn_change(Path('/tmp/seguro.opts'), 'enableClient')
            self.assertEqual(called.call_args.args[0][-1], 'bridge')
    def test_arquivo_privado(self):
        target = self.root / 'private'
        mod.private_file(target, b'abc')
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(target.read_bytes(), b'abc')
    def test_arquivo_privado_nao_sobrescreve(self):
        target = self.root / 'private'
        mod.private_file(target, b'abc')
        with self.assertRaises((FileExistsError, mod.p2.Block)):
            mod.private_file(target, b'def')
        self.assertEqual(target.read_bytes(), b'abc')

    def state(self, *, ids=None, defaults=None, extra=None, roles=None):
        mapping = {u: (('publishClientSend', f'lab/{u}'),) for u in mod.p4b.ACCOUNTS}
        clients = []
        r = []
        for u in mod.p4b.ACCOUNTS:
            clients.append({'username': u, 'clientid': (ids or {}).get(u, mod.IDS[u]),
                            'roles': [{'rolename': mod.p4b.role_name(u), 'priority': 10}], 'groups': []})
            r.append({'rolename': mod.p4b.role_name(u),
                      'acls': [{'acltype': 'publishClientSend', 'topic': f'lab/{u}', 'allow': True}]})
        clients.append({'username': mod.p4b.ADMIN})
        if extra: clients.append(extra)
        if roles: r[0]['acls'] = roles
        data = {'defaultACLAccess': defaults or {k: False for k in mod.p4b.DEFAULTS},
                'clients': clients, 'roles': r}
        path = self.root / 'state.json'
        path.write_text(json.dumps(data))
        path.chmod(0o600)
        return path, mapping

    def test_estado_valido(self):
        state, mapping = self.state()
        mod.verify_candidate(state, mapping)
    def test_estado_id_errado(self):
        state, mapping = self.state(ids={'bridge': 'phase8454b-bridge'})
        with self.assertRaises(mod.Block): mod.verify_candidate(state, mapping)
    def test_estado_default_allow(self):
        defaults = {k: False for k in mod.p4b.DEFAULTS}; defaults['unsubscribe'] = True
        state, mapping = self.state(defaults=defaults)
        with self.assertRaises(mod.Block): mod.verify_candidate(state, mapping)
    def test_estado_usuario_extra(self):
        state, mapping = self.state(extra={'username': 'sensor01'})
        with self.assertRaises(mod.Block): mod.verify_candidate(state, mapping)
    def test_estado_acls_expandidas(self):
        acl = [{'acltype': 'publishClientSend', 'topic': '#', 'allow': True}]
        state, mapping = self.state(roles=acl)
        with self.assertRaises(mod.Block): mod.verify_candidate(state, mapping)
    def test_estado_acl_negada_extra(self):
        acl = [{'acltype': 'publishClientSend', 'topic': 'lab/lab', 'allow': True},
               {'acltype': 'publishClientSend', 'topic': '#', 'allow': False}]
        state, mapping = self.state(roles=acl)
        with self.assertRaises(mod.Block): mod.verify_candidate(state, mapping)
    def test_estado_json_invalido(self):
        state, mapping = self.state()
        state.write_text('{')
        with self.assertRaises(mod.Block): mod.verify_candidate(state, mapping)
    def test_estado_permissao_publica(self):
        state, mapping = self.state()
        state.chmod(0o644)
        with self.assertRaises(mod.p2.Block): mod.verify_candidate(state, mapping)
    def test_preflight_sem_cargo(self):
        with patch.object(mod.p4b, 'preflight', return_value={}), \
             patch.object(mod, 'check_source'), \
             patch.object(mod.shutil, 'which', return_value=None):
            with self.assertRaises(mod.Block): mod.preflight(self.root, self.root, self.root, self.root, self.root)
    def test_preflight_porta_8895_ocupada(self):
        with patch.object(mod.p4b, 'preflight', return_value={}), \
             patch.object(mod, 'check_source'), \
             patch.object(mod.shutil, 'which', return_value='/usr/bin/cargo'), \
             patch.object(mod.p3, 'available', return_value=False):
            with self.assertRaises(mod.Block): mod.preflight(self.root, self.root, self.root, self.root, self.root)
    def test_preflight_aprovado(self):
        with patch.object(mod.p4b, 'preflight', return_value={'bridge': 1}), \
             patch.object(mod, 'check_source'), \
             patch.object(mod.shutil, 'which', return_value='/usr/bin/cargo'), \
             patch.object(mod.p3, 'available', return_value=True):
            self.assertEqual(mod.preflight(self.root, self.root, self.root, self.root, self.root), {'bridge': 1})
    def test_probe_timeout_sem_sucesso(self):
        fake = object.__new__(mod.RustProbe)
        fake.proc = Mock(); fake.proc.poll.return_value = None
        fake.stdout = queue.Queue()
        with self.assertRaises(mod.Block): fake.wait_output('IN alerts exemplo', 0.01)
    def test_probe_evento_exato(self):
        fake = object.__new__(mod.RustProbe)
        fake.proc = Mock(); fake.proc.poll.return_value = None
        fake.stdout = queue.Queue(); fake.stdout.put('IN alerts correto')
        self.assertEqual(fake.wait_output('IN alerts correto', 1), 'IN alerts correto')
    def test_probe_conectado(self):
        fake = object.__new__(mod.RustProbe)
        fake.proc = Mock(); fake.proc.poll.return_value = None
        fake.connections = queue.Queue(); fake.connections.put('CONNECTED')
        fake.connected(0.01)
    def test_probe_sem_conexao(self):
        fake = object.__new__(mod.RustProbe)
        fake.proc = Mock(); fake.proc.poll.return_value = None
        fake.connections = queue.Queue()
        with self.assertRaises(mod.Block): fake.connected(0.01)
    def test_probe_publicacao_comando_seguro(self):
        fake = object.__new__(mod.RustProbe)
        fake.proc = Mock()
        fake.proc.stdin = Mock()
        fake.wait_output = Mock(return_value='QUEUED c1-ok')
        fake.publish_bus('c1-ok')
        fake.proc.stdin.write.assert_called_once_with('PUB c1-ok\n')
    def test_probe_publicacao_payload_malicioso(self):
        fake = object.__new__(mod.RustProbe)
        fake.proc = Mock()
        with self.assertRaises(mod.Block): fake.publish_bus('c1-\nSTOP')
    def test_codigo_rust_nao_chama_binario_principal(self):
        rust = (Path(__file__).resolve().parent.parent / 'scripts' / mod.PROBE_SOURCE).read_text()
        self.assertIn('bridge::start(', rust)
        self.assertIn('127.0.0.1:8895', rust)
        self.assertNotIn('8883', rust)
        self.assertNotIn('8884', rust)
        self.assertNotIn('include!("../src/main.rs")', rust)
    def test_env_nao_transfere_segredos(self):
        with patch.dict(os.environ, {'RUST_SERVER_MQTT_BRIDGE_PASSWORD': 'SECRET',
                                     'GITHUB_TOKEN': 'SECRET', 'PATH': '/usr/bin'}):
            env = mod.restricted_env()
            self.assertNotIn('GITHUB_TOKEN', env)
            self.assertNotIn('RUST_SERVER_MQTT_BRIDGE_PASSWORD', env)
            self.assertEqual(env['PATH'], '/usr/bin')

    def test_build_offline_e_scratch(self):
        # Nao compila aqui: verifica o contrato sem executar cargo.
        fake_proc = Mock(returncode=0)
        def fake_run(args, **kwargs):
            self.assertIn('--offline', args)
            self.assertIn('--manifest-path', args)
            self.assertTrue(str(kwargs['cwd']).startswith(str(self.root)))
            target = kwargs['env']['CARGO_TARGET_DIR']
            self.assertTrue(target.startswith(str(self.root)))
            dst = Path(target)/'debug'/mod.PROBE_NAME
            dst.parent.mkdir(parents=True, exist_ok=True); dst.write_text('fake')
            return fake_proc
        with patch.object(mod.subprocess, 'run', side_effect=fake_run):
            out = mod.build_probe(self.root, self.root)
            self.assertTrue(out.is_file())
            self.assertFalse((self.root/'Cargo.lock').exists())
    def test_build_ativa_provedor_ring_no_manifest_temporario(self):
        # Regressao do erro E0433: rustls::crypto::ring estava desabilitado.
        fake_proc = Mock(returncode=0)
        def fake_run(args, **kwargs):
            manifest = Path(kwargs['cwd']) / 'Cargo.toml'
            content = manifest.read_text()
            self.assertIn('rustls = { version = "0.23", default-features = false, features = ["ring"] }', content)
            self.assertIn('rumqttc = { version = "=0.25.1"', content)
            self.assertIn('--offline', args)
            output = Path(kwargs['env']['CARGO_TARGET_DIR']) / 'debug' / mod.PROBE_NAME
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text('fake')
            return fake_proc
        with patch.object(mod.subprocess, 'run', side_effect=fake_run):
            self.assertTrue(mod.build_probe(self.root, self.root).is_file())

    def test_build_compilacao_falha_fecha(self):
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=1)):
            with self.assertRaises(mod.Block): mod.build_probe(self.root, self.root)
    def test_listener_absent_sem_listener_8895(self):
        result = Mock(returncode=0, stdout='LISTEN 0 128 127.0.0.1:8883 0.0.0.0:*\n')
        with patch.object(mod.subprocess, 'run', return_value=result) as run:
            self.assertTrue(mod.listener_absent(8895))
            run.assert_called_once()
            self.assertEqual(run.call_args.args[0], ['ss', '-H', '-lnt'])

    def test_listener_absent_detecta_ipv4_e_ipv6(self):
        for addr in ('127.0.0.1:8895', '0.0.0.0:8895', '[::1]:8895', '*:8895'):
            with self.subTest(addr=addr), patch.object(mod.subprocess, 'run',
                    return_value=Mock(returncode=0, stdout=f'LISTEN 0 128 {addr} 0.0.0.0:*\n')):
                self.assertFalse(mod.listener_absent(8895))

    def test_listener_absent_rejeita_falha_consulta(self):
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=1, stdout='')):
            with self.assertRaises(mod.Block): mod.listener_absent(8895)
        with self.assertRaises(mod.Block): mod.listener_absent(8883)

    def test_broker_for_bridge_encerra_somente_filho(self):
        child = Mock()
        child.poll.return_value = None
        with patch.object(mod.p3, 'available', return_value=True), \
             patch.object(mod, 'listener_absent', return_value=True), \
             patch.object(mod.p3, 'port_alive', return_value=True), \
             patch.object(mod.subprocess, 'Popen', return_value=child):
            with mod.broker_for_bridge(self.root / 'candidate.conf', 8895):
                pass
        child.terminate.assert_called_once()
        child.wait.assert_called_once_with(timeout=4)
        child.kill.assert_not_called()

    def test_broker_for_bridge_nega_listener_restante(self):
        child = Mock()
        child.poll.return_value = None
        with patch.object(mod.p3, 'available', return_value=True), \
             patch.object(mod, 'listener_absent', side_effect=[True, False]), \
             patch.object(mod.p3, 'port_alive', return_value=True), \
             patch.object(mod.subprocess, 'Popen', return_value=child), \
             patch.object(mod.time, 'sleep'), patch.object(mod.time, 'monotonic', side_effect=[1, 1, 9, 12]):
            with self.assertRaises(mod.Block):
                with mod.broker_for_bridge(self.root / 'candidate.conf', 8895):
                    pass
        child.terminate.assert_called_once()

    def test_ensaio_c1_nao_usa_broker_generico(self):
        import inspect
        source = inspect.getsource(mod.run)
        self.assertIn('with broker_for_bridge(config, PORT):', source)
        self.assertNotIn('p3.available(PORT) and p3.available(8896)', source)
        self.assertIn('listener_absent(PORT) and listener_absent(8896)', source)

    def test_estados_importantes(self):
        self.assertEqual(mod.PORT, 8895)
        self.assertEqual(mod.HOST, '127.0.0.1')
        self.assertEqual(mod.PROBE_NAME, 'phase8454c1_probe')

if __name__ == '__main__':
    unittest.main(verbosity=2)
