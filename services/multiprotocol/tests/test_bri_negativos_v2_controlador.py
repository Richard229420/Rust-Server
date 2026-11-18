#!/usr/bin/env python3
"""Teste isolado dos metadados/ACL temporaria; nao cria broker nem credenciais operacionais."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
import sys
sys.path.insert(0, str(SCRIPTS))
import testar_bridge_bri_negativos_v2_8901 as mod


class TemporaryACL(unittest.TestCase):
    def test_cases_are_explicit(self):
        self.assertEqual(mod.CASES, ('auth_rejeitada', 'ca_nao_confiavel', 'acl_entrega_negada'))

    def test_auditor_only_in_temporary_files(self):
        with tempfile.TemporaryDirectory() as t:
            tmp = Path(t)
            mod.base.write_private(tmp/'passwords', 'bridge:existinghash\ninjector:existinghash\n')
            mod.base.write_private(tmp/'acl', 'user bridge\ntopic write bus/alerts\n'
                                   'user injector\ntopic write lab/alerts\n')
            def emulate_hash(*argv):
                self.assertEqual(argv[:2], ('mosquitto_passwd', '-U'))
                Path(argv[2]).write_text('auditor:hashedvalue\n')
            with patch.object(mod.base, 'call', side_effect=emulate_hash):
                mod.add_auditor(tmp)
            self.assertIn('bridge:existinghash\n', (tmp/'passwords').read_text())
            self.assertIn('auditor:hashedvalue\n', (tmp/'passwords').read_text())
            self.assertIn('user auditor\ntopic read bus/alerts\n', (tmp/'acl').read_text())
            self.assertNotIn('topic read bus/#', (tmp/'acl').read_text())
            self.assertFalse((tmp/'auditor.passwd.tmp').exists())
            self.assertEqual((tmp/'auditor.pw').stat().st_mode & 0o777, 0o600)

    def test_no_operational_filenames(self):
        source = mod.Path(mod.__file__).read_text()
        for token in ('renovacao-mqtt-staging', 'systemctl', 'mosquitto_ctrl', 'RUST_SERVER_MQTT_ADDR'):
            self.assertNotIn(token, source)


if __name__ == '__main__':
    unittest.main()
