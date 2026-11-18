#!/usr/bin/env python3
"""Teste isolado do auditor 8.4.5.1; fixtures artificiais, sem estado real."""
from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'scripts/fase8_4_5_1_auditoria.py'
spec = importlib.util.spec_from_file_location('audit8451', SCRIPT)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def put(p: Path, data: str, private=True):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data, encoding='utf-8')
    p.chmod(0o600 if private else 0o644)
    return p


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='audit8451-')
        self.addCleanup(self.tmp.cleanup)
        home = Path(self.tmp.name)
        self.project = home / 'project'
        self.root = home / 'private'
        self.mosq = self.root / 'mosquitto'
        self.lab = self.root / 'phase8-4-2-lab'
        self.plugin = home / 'lib' / 'mosquitto_dynamic_security.so'
        for d in (self.project, self.project/'certs', self.root, self.mosq,
                  self.lab, self.lab/'pki', self.lab/'clients', self.plugin.parent):
            d.mkdir(parents=True, exist_ok=True)
            d.chmod(0o700)
        put(self.plugin, 'fake shared object')
        for f in ('ca.crt', 'localhost.crt'):
            put(self.project/'certs'/f, 'public test certificate', private=False)
        put(self.project/'certs/localhost.key', 'DO-NOT-PRINT-PRIVATE-KEY')
        self.legacy_config = (
            'listener 8883 127.0.0.1\nallow_anonymous false\n'
            f'password_file {self.mosq}/passwords\nacl_file {self.mosq}/acl\n'
            f'certfile {self.project}/certs/localhost.crt\n'
            f'keyfile {self.project}/certs/localhost.key\n'
            'tls_version tlsv1.2\npersistence false\nmax_connections 64\n'
        )
        put(self.mosq/'mosquitto.conf', self.legacy_config)
        put(self.mosq/'devices.json', json.dumps({'version': 1, 'devices': {
            'sensor01': {'state': 'revoked'}, 'sensor02': {'state': 'active'},
        }}))
        put(self.mosq/'passwords', 'bridge:$REDACTED_HASH\nlab:$REDACTED_HASH\n'
            'device-sensor02:$REDACTED_HASH\n')
        put(self.mosq/'acl', '\n'.join([
            '# ACL baseline',
            'user bridge', 'topic read lab/alerts', 'topic read lab/sensors/#',
            'topic write bus/alerts', 'topic write bus/sensors/#',
            'user lab', 'topic write lab/alerts', 'topic read bus/alerts',
            '# BEGIN FASE8.3 DEVICES',
            'user device-sensor02', 'topic write lab/sensors/sensor02/#',
            'topic read bus/sensors/sensor02/#',
            '# END FASE8.3 DEVICES', '',
        ]))
        self.lab_config = (
            'persistence false\nlog_dest stdout\n'
            f'plugin_load labdynsec {self.plugin}\n'
            f'plugin_opt_config_file {self.lab}/dynamic-security.json\n'
            'listener 8884 127.0.0.1\nlistener_allow_anonymous false\n'
            f'certfile {self.lab}/pki/server.crt\n'
            f'keyfile {self.lab}/pki/server.key\n'
            f'cafile {self.lab}/pki/ca.crt\n'
            'tls_version tlsv1.2\nplugin_use labdynsec\n'
        )
        put(self.lab/'mosquitto-lab.conf', self.lab_config)
        put(self.lab/'dynamic-security.json', '{"SECRET_PLAINTEXT":"DO_NOT_ECHO"}')
        for n in ('ca.crt', 'server.crt', 'server.key'):
            put(self.lab/'pki'/n, 'DO_NOT_PRINT_TLS_KEY')
        for n in ('device-sensor01.opts', 'device-sensor02.opts', 'lab84-bridge.opts'):
            put(self.lab/'clients'/n, 'DO_NOT_PRINT_CLIENT_PASSWORD')
        put(self.lab/'fase8_4_4_state.json', json.dumps({'phase': '8.4.4',
            'stage': 'completed', 'target': 'device-sensor01', 'port': 8884}))

    def run_audit(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            result = audit.audit(self.project, self.root, self.plugin, False)
        return result, buf.getvalue()

    def test_baseline_aceito_sem_autorizacao_de_migracao(self):
        code, result = self.run_audit()
        self.assertEqual(code, 0, result)
        self.assertIn('MIGRACAO REAL NAO AUTORIZADA', result)
        self.assertIn('bloqueios=0', result)

    def test_nao_expoe_segredos(self):
        code, result = self.run_audit()
        self.assertEqual(code, 0)
        for v in ('DO_NOT_ECHO', 'DO_NOT_PRINT', 'REDACTED_HASH'):
            self.assertNotIn(v, result)

    def test_leitura_nao_altera_arquivos(self):
        tracked = [self.mosq/'mosquitto.conf', self.mosq/'passwords', self.mosq/'acl',
                   self.lab/'dynamic-security.json', self.lab/'pki/server.key']
        before = [(f.stat().st_mtime_ns, f.read_bytes()) for f in tracked]
        self.run_audit()
        after = [(f.stat().st_mtime_ns, f.read_bytes()) for f in tracked]
        self.assertEqual(before, after)

    def test_conta_revogada_inadvertidamente_ativa(self):
        with (self.mosq/'passwords').open('a') as handle:
            handle.write('device-sensor01:$LEAK\n')
        code, output = self.run_audit()
        self.assertEqual(code, 2)
        self.assertIn('contas: inventario, senhas e revogacoes coerentes', output)

    def test_acl_cross_sensor_bloqueia(self):
        p = self.mosq/'acl'
        p.write_text(p.read_text() + 'topic read bus/sensors/sensor01/#\n')
        self.assertEqual(self.run_audit()[0], 2)

    def test_plugin_no_broker_original_bloqueia(self):
        put(self.mosq/'mosquitto.conf', self.legacy_config + 'plugin_use labdynsec\n')
        self.assertEqual(self.run_audit()[0], 2)

    def test_listener_exposto_bloqueia(self):
        put(self.lab/'mosquitto-lab.conf', self.lab_config.replace('8884 127.0.0.1', '8884 0.0.0.0'))
        self.assertEqual(self.run_audit()[0], 2)

    def test_opcoes_nao_privadas_bloqueiam(self):
        (self.lab/'clients/device-sensor02.opts').chmod(0o644)
        self.assertEqual(self.run_audit()[0], 2)

    def test_symlink_nao_e_lido(self):
        p = self.lab/'dynamic-security.json'
        outside = Path(self.tmp.name)/'outside'
        put(outside, 'DO_NOT_PRINT_SECRET')
        p.unlink()
        p.symlink_to(outside)
        code, output = self.run_audit()
        self.assertEqual(code, 2)
        self.assertNotIn('DO_NOT_PRINT_SECRET', output)

    def test_marcador_incompleto_bloqueia(self):
        put(self.lab/'fase8_4_4_state.json', '{"phase":"8.4.4","stage":"disable-requested"}')
        self.assertEqual(self.run_audit()[0], 2)

    def test_dispositivo_ausente_bloqueia(self):
        (self.mosq/'devices.json').unlink()
        self.assertEqual(self.run_audit()[0], 2)

    def test_criptografia_arquivo_privado_bloqueada(self):
        (self.project/'certs/localhost.key').chmod(0o644)
        self.assertEqual(self.run_audit()[0], 2)

    def test_nao_exige_brokers_ativos(self):
        self.assertEqual(self.run_audit()[0], 0)

    def test_cfg_incluido_ou_anonimo_bloqueia(self):
        put(self.lab/'mosquitto-lab.conf', self.lab_config + 'allow_anonymous true\n')
        self.assertEqual(self.run_audit()[0], 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
