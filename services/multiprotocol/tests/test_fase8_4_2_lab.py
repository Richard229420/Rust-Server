#!/usr/bin/env python3
"""Testes offline de 8.4.2 (dados em temporarios, sem Mosquitto em execucao)."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'fase8_4_2_lab.py'
spec = importlib.util.spec_from_file_location('lab842', MODULE)
lab = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lab)


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='rust84-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name) / 'settings'
        self.base.mkdir(mode=0o700)
        self.root = self.base / 'phase8-4-2-lab'
        p = mock.patch.object(lab, 'ROOT', self.root)
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(lab, 'preflight')
        p.start()
        self.addCleanup(p.stop)

    def make_lab(self):
        lab.init_dirs()
        for rel in ('mosquitto-lab.conf', 'dynamic-security.json', 'pki/ca.crt', 'pki/server.crt', 'pki/server.key'):
            lab.safe_write(self.root / rel, 'test')
        (self.root / 'mosquitto-lab.conf').write_text(
            f'listener 8884 127.0.0.1\nlistener_allow_anonymous false\nplugin_use labdynsec\n'
            f'plugin_opt_config_file {self.root / "dynamic-security.json"}\n')

    def test_diretorios_privados(self):
        lab.init_dirs()
        self.assertEqual(stat.S_IMODE(self.root.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.root / 'pki').stat().st_mode), 0o700)

    def test_nao_sobrescreve(self):
        lab.init_dirs()
        with self.assertRaises(lab.Abort):
            lab.init_dirs()
        lab.safe_write(self.root / 'secret', 'a')
        with self.assertRaises(lab.Abort):
            lab.safe_write(self.root / 'secret', 'b')

    def test_proibe_symlink(self):
        lab.init_dirs()
        target = self.root / 'orig'
        lab.safe_write(target, 'priv')
        link = self.root / 'link'
        link.symlink_to(target)
        with self.assertRaises(lab.Abort):
            lab.check_private(link)

    def test_rejeita_credencial_publica(self):
        lab.init_dirs()
        path = self.root / 'cred'
        lab.safe_write(path, 'data')
        path.chmod(0o644)
        with self.assertRaises(lab.Abort):
            lab.check_private(path)

    def test_arquivo_client_options_apenas_loopback(self):
        opts = lab.secure_client_options('device-sensor01', 'lab84-sensor01', 'secretXYZ')
        self.assertIn('-h localhost\n-p 8884\n', opts)
        self.assertIn('pki/ca.crt', opts)
        self.assertNotIn('8883', opts)

    def test_validacao_configuracao(self):
        self.make_lab()
        lab.validated_root()
        bad = self.root / 'mosquitto-lab.conf'
        bad.write_text('listener 8883 0.0.0.0')
        with self.assertRaises(lab.Abort):
            lab.validated_root()

    def test_preparacao_tls_criptografada_e_isolada(self):
        # Geracao real de certificado no diretorio temporario.
        with mock.patch('getpass.getpass', side_effect=['SenhaAdmin-Segura-Exclusiva-8.4.2', 'SenhaAdmin-Segura-Exclusiva-8.4.2']), \
             mock.patch.object(lab, 'command', wraps=lab.command) as run:
            def cmd(args, **kwargs):
                if args[:3] == ['mosquitto_ctrl','dynsec','init']:
                    lab.safe_write(self.root / 'dynamic-security.json', json.dumps({'clients':[]}))
                    return 'ok'
                return lab.command_original(args, **kwargs)
            lab.command_original = lab.command
            with mock.patch.object(lab, 'command', side_effect=cmd):
                lab.prepare()
        cfg = (self.root / 'mosquitto-lab.conf').read_text()
        self.assertIn('plugin_load labdynsec', cfg)
        self.assertIn('plugin_use labdynsec', cfg)
        self.assertIn('listener_allow_anonymous false', cfg)
        self.assertIn('listener 8884 127.0.0.1', cfg)
        self.assertNotIn('/home/arch/server', cfg)
        lab.check_private(self.root / 'pki/ca.key')
        lab.check_private(self.root / 'dynamic-security.json')

    def test_provisiona_acl_deny_e_credenciais_em_arquivo_privado(self):
        self.make_lab()
        calls = []
        def fake(ctrl, *args, **kwargs):
            calls.append((args, kwargs))
        with mock.patch.object(lab, 'port_open', return_value=True), \
             mock.patch('getpass.getpass', return_value='SenhaAdmin-Segura-Exclusiva-8.4.2'), \
             mock.patch.object(lab, 'invoke_control', side_effect=fake):
            lab.provision()
        defaults = [args for args, _ in calls if args and args[0] == 'setDefaultACLAccess']
        self.assertEqual(len(defaults), 4)
        self.assertTrue(all(args[2] == 'deny' for args in defaults))
        creates = [args for args,_ in calls if args and args[0] == 'createClient']
        self.assertEqual(len(creates), 3)
        for username in lab.CLIENTS:
            lab.check_private(self.root / 'clients' / (username + '.opts'))
        for args, kwargs in calls:
            if args and args[0] == 'createClient':
                self.assertNotIn(' ', args[1])
                self.assertEqual(len(args), 2) # nenhum segredo na linha de comando
                self.assertTrue(kwargs['input_text'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
