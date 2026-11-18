#!/usr/bin/env python3
"""Testes locais sem broker, sem pacman, sem tocar no HOME real."""
from __future__ import annotations
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'fase8_4_1_inventario_backup.py'
spec = importlib.util.spec_from_file_location('fase841', MODULE)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='rust-fase841-')
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.project = base / 'server' / 'services' / 'multiprotocol'
        self.root = base / 'config' / 'rust-server'
        self.backups = base / 'backups'
        self.plugin = base / 'usr' / 'mosquitto_dynamic_security.so'
        self.plugin.parent.mkdir(parents=True)
        self.plugin.write_bytes(b'test fixture only')
        for d in [self.root, self.root / 'mosquitto', self.root / 'device-tokens', self.project / 'certs']:
            d.mkdir(parents=True, exist_ok=True, mode=0o700)
            d.chmod(0o700)
        broker = self.root / 'mosquitto'
        self._put(broker / 'mosquitto.conf', (
            'listener 8883 127.0.0.1\nallow_anonymous false\n'
            f'password_file {broker / "passwords"}\n'
            f'acl_file {broker / "acl"}\n'
            f'certfile {self.project / "certs/localhost.crt"}\n'
            f'keyfile {self.project / "certs/localhost.key"}\n'))
        self._put(broker / 'passwords', 'bridge:$7$dummy\nlab:$7$dummy\n')
        self._put(broker / 'acl', 'user bridge\ntopic read lab/sensors/#\n')
        self._put(broker / 'devices.json', json.dumps({'devices': {'sensor01': {'state': 'revoked'}, 'sensor02': {'state': 'active'}}}))
        self._put(self.root / 'mqtt-bridge.token', 'secret-for-test')
        self._put(self.root / 'mqtt-lab.token', 'secret-for-test-2')
        self._put(self.root / 'device-tokens/sensor02.token', 'secret-for-test-3')
        self._put(self.project / 'certs/ca.crt', 'cert-ca')
        self._put(self.project / 'certs/localhost.crt', 'cert-localhost')
        self._put(self.project / 'certs/localhost.key', 'key-localhost')

    def _put(self, p: Path, content: str):
        p.write_text(content)
        p.chmod(0o600)

    def _make(self):
        return mod.backup(self.project, self.root, self.backups, self.plugin)

    def test_inventario_backup_verificacao_simulacao(self):
        self.assertEqual(mod.inventory(self.project, self.root, self.plugin), 0)
        snapshot = self._make()
        files = mod.verify(snapshot)
        self.assertEqual(len(files), 10)
        mod.simulate(snapshot, self.backups)
        self.assertEqual((snapshot / 'payload/mosquitto/passwords').stat().st_mode & 0o777, 0o600)
        self.assertEqual(snapshot.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.project / 'certs/dynamic-security.json').exists())
        self.assertFalse(any(self.backups.glob('.restauracao-simulada-*')))

    def test_detecta_alteracao_em_backup(self):
        snapshot = self._make()
        self._put(snapshot / 'payload/mosquitto/passwords', 'alterado')
        with self.assertRaises(mod.Abort):
            mod.verify(snapshot)

    def test_nao_segue_symlink_de_token(self):
        target = self.root / 'mqtt-lab.token'
        token = self.root / 'device-tokens/sensor02.token'
        token.unlink()
        token.symlink_to(target)
        with self.assertRaises(mod.Abort):
            self._make()
        self.assertFalse(self.backups.exists() and any(self.backups.iterdir()))

    def test_rejeita_arquivo_privado_publico(self):
        (self.root / 'mosquitto/passwords').chmod(0o644)
        with self.assertRaises(mod.Abort):
            self._make()

    def test_rejeita_backup_no_diretorio_do_projeto(self):
        with self.assertRaises(mod.Abort):
            mod.backup(self.project, self.root, self.project / 'target/backups', self.plugin)

    def test_rejeita_config_alterada_ou_dynsec_precoce(self):
        conf = self.root / 'mosquitto/mosquitto.conf'
        self._put(conf, conf.read_text() + 'global_plugin /usr/lib/mosquitto_dynamic_security.so\n')
        with self.assertRaises(mod.Abort):
            self._make()

    def test_rejeita_manifesto_traversal(self):
        snapshot = self._make()
        manifest = snapshot / 'manifest.json'
        data = json.loads(manifest.read_text())
        data['files'][0]['path'] = '../fora'
        self._put(manifest, json.dumps(data))
        with self.assertRaises(mod.Abort):
            mod.verify(snapshot)

if __name__ == '__main__':
    unittest.main(verbosity=2)
