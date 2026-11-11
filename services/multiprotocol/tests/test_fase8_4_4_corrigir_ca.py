#!/usr/bin/env python3
"""Regressao offline da reemissao privada da CA; nunca usa broker real."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fase8_4_4_corrigir_ca as fix


class FixTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ca844-test-')
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name) / 'phase8-4-2-lab'
        root.mkdir(mode=0o700)
        (root/'pki').mkdir(mode=0o700)
        self.root = root
        self.patches = [mock.patch.object(fix, 'ROOT', root),
                        mock.patch.object(fix.lab, 'ROOT', root),
                        mock.patch.object(fix.online, 'ROOT', root),
                        mock.patch.object(fix.lab, 'validated_root', return_value=None),
                        mock.patch.object(fix.lab, 'port_open', return_value=True),
                        mock.patch.object(fix.os, 'geteuid', return_value=1000)]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        (root/'mosquitto-lab.conf').write_text('plugin_use labdynsec\n')
        p = root/'pki'
        def openssl(*argv):
            subprocess.run(['openssl', *map(str,argv)], check=True, capture_output=True)
        # Forcar CA antiga sem keyUsage, independentemente do openssl.cnf do host.
        (p/'old-ca.cnf').write_text('[ req ]\nprompt = no\ndistinguished_name = dn\n'
                                    'x509_extensions = v3_ca\n[ dn ]\n'
                                    'CN = Rust-Server MQTT Lab CA 8.4.2\n'
                                    '[ v3_ca ]\nsubjectKeyIdentifier = hash\n'
                                    'authorityKeyIdentifier = keyid:always\n'
                                    'basicConstraints = critical, CA:TRUE\n')
        openssl('req','-x509','-newkey','rsa:2048','-sha256','-nodes','-days','30',
                '-config',p/'old-ca.cnf','-extensions','v3_ca',
                '-keyout',p/'ca.key', '-out',p/'ca.crt')
        openssl('req','-new','-newkey','rsa:2048','-sha256','-nodes','-subj','/CN=localhost',
                '-keyout',p/'server.key','-out',p/'server.csr')
        (p/'san.cnf').write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\n'
                                 'basicConstraints=critical,CA:FALSE\n'
                                 'keyUsage=digitalSignature,keyEncipherment\n'
                                 'extendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
        openssl('x509','-req','-in',p/'server.csr','-CA',p/'ca.crt','-CAkey',p/'ca.key',
                '-CAcreateserial','-out',p/'server.crt','-days','30','-sha256','-extfile',p/'san.cnf')
        for file in p.iterdir():
            file.chmod(0o600)
        self.server_hash = fix.sha((p/'server.crt').read_bytes())
        self.key_hash = fix.sha((p/'ca.key').read_bytes())
        self.ca_hash = fix.sha((p/'ca.crt').read_bytes())

    def test_antigo_certificado_nao_passa_estrito(self):
        ca, key, server = fix.inspect_paths()
        self.assertTrue(fix.verify(server, ca, False))
        self.assertFalse(fix.verify(server, ca, True))

    def test_corrige_sem_trocar_chaves_ou_leaf(self):
        with mock.patch.object(fix, 'tls_probe', return_value=None):
            fix.repair()
        p = self.root/'pki'
        self.assertTrue(fix.verify(p/'server.crt', p/'ca.crt', True))
        self.assertNotEqual(fix.sha((p/'ca.crt').read_bytes()), self.ca_hash)
        self.assertEqual(fix.sha((p/'server.crt').read_bytes()), self.server_hash)
        self.assertEqual(fix.sha((p/'ca.key').read_bytes()), self.key_hash)
        self.assertEqual(fix.sha((p/fix.BACKUP_NAME).read_bytes()), self.ca_hash)
        self.assertFalse((self.root/'fase8_4_4_state.json').exists())

    def test_reexecucao_nao_sobrescreve(self):
        with mock.patch.object(fix, 'tls_probe', return_value=None):
            fix.repair()
            fix.repair()
        self.assertEqual(len(list((self.root/'pki').glob('*.backup'))), 1)

    def test_bloqueia_se_marcador_existe(self):
        fix.online.write_state('prepared')
        with self.assertRaises(fix.Fail):
            fix.repair()
        self.assertEqual(fix.sha((self.root/'pki'/'ca.crt').read_bytes()), self.ca_hash)

    def test_bloqueia_se_chave_incompativel(self):
        other = self.root/'other.key'
        subprocess.run(['openssl','genrsa','-out', str(other),'2048'], check=True, capture_output=True)
        (self.root/'pki'/'ca.key').write_bytes(other.read_bytes())
        with self.assertRaises(fix.Fail):
            fix.inspect_paths()

if __name__ == '__main__':
    unittest.main(verbosity=2)
