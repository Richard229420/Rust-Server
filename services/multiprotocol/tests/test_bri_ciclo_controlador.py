#!/usr/bin/env python3
"""Testes locais do controlador, sem abrir portas ou executar comandos externos."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "testar_bridge_bri_ciclo_8901.py"
spec = importlib.util.spec_from_file_location("bri_ciclo", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)


class Tests(unittest.TestCase):
    def test_porta_isolada(self):
        self.assertEqual(module.PORT, 8901)
        src = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn("systemctl", src)
        self.assertNotIn(chr(34) + "sudo" + chr(34) + ",", src)
        self.assertNotIn("pkill", src)
        self.assertNotIn("/etc/mosquitto", src)

    def test_acl_explicita_e_privada(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            module.config(root)
            acl = (root / "acl").read_text()
            self.assertIn("topic read lab/alerts", acl)
            self.assertIn("topic write lab/alerts", acl)
            self.assertNotIn("topic read #", acl)
            self.assertEqual((root / "mosquitto.conf").stat().st_mode & 0o777, 0o600)
            self.assertIn("listener 8901 127.0.0.1", (root / "mosquitto.conf").read_text())

    def test_nao_expoe_senha_em_argumentos(self):
        src = SCRIPT.read_text(encoding="utf-8")
        self.assertNotIn('"-P"', src)
        self.assertIn('BRI_LAB_BRIDGE_PWFILE', src)
        self.assertIn('BRI_LAB_INJECTOR_PWFILE', src)
        self.assertIn('secret', src)

    def test_marcador_tem_namespace_distinto(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            # No subprocesses, only the actual marker derivation method.
            obj = object.__new__(module.Lab)
            obj.nonce = "ab12"
            self.assertEqual(obj.marker("RECONEXAO"), "BRI_TEST_ab12_RECONEXAO")

    def test_senha_hasheada_um_unico_passo(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            with patch.object(module, "call") as call_mock:
                module.passwords(root, "old-test", "injector-test")
                call_mock.assert_called_once_with(
                    "mosquitto_passwd", "-U", str(root / "passwords")
                )
                self.assertEqual((root / "passwords").stat().st_mode & 0o777, 0o600)
                self.assertIn("bridge:old-test", (root / "passwords").read_text())


if __name__ == "__main__":
    unittest.main(verbosity=2)
