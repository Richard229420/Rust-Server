import configparser
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


BASE = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "systemd"
)

MODELOS = {
    "rust-server-mqtt-lab-8884.service": {
        "Unit": {
            "Description": "Rust-Server MQTT Lab 8884 - Template DR",
            "StartLimitIntervalSec": "60",
            "StartLimitBurst": "3",
        },
        "Service": {
            "Type": "simple",
            "ExecStart": "/usr/bin/false",
            "Restart": "on-failure",
            "RestartSec": "5",
            "UMask": "0077",
            "NoNewPrivileges": "true",
        },
        "Install": {
            "WantedBy": "default.target",
        },
    },
    "rust-server-mqtt-tls-monitor.service": {
        "Unit": {
            "Description": "Rust-Server MQTT TLS Monitor - Template DR",
        },
        "Service": {
            "Type": "oneshot",
            "ExecStart": "/usr/bin/false",
        },
    },
    "rust-server-mqtt-tls-monitor.timer": {
        "Unit": {
            "Description": "Rust-Server MQTT TLS Monitor Timer - Template DR",
        },
        "Timer": {
            "OnCalendar": "*-*-* 09:00:00",
            "Persistent": "true",
            "AccuracySec": "5min",
            "Unit": "rust-server-mqtt-tls-monitor.service",
        },
        "Install": {
            "WantedBy": "timers.target",
        },
    },
}


class TestDR05Systemd(unittest.TestCase):

    def test_modelos_existem(self):
        for nome in MODELOS:
            with self.subTest(nome=nome):
                arquivo = BASE / f"{nome}.example"
                self.assertTrue(arquivo.is_file())
                self.assertFalse(arquivo.is_symlink())

    def test_estrutura_aprovada(self):
        for nome, esperado in MODELOS.items():
            with self.subTest(nome=nome):
                arquivo = BASE / f"{nome}.example"

                parser = configparser.ConfigParser(
                    interpolation=None,
                    delimiters=("=",),
                    strict=True,
                )
                parser.optionxform = str
                parser.read(arquivo, encoding="utf-8")

                obtido = {
                    secao: dict(parser.items(secao))
                    for secao in parser.sections()
                }

                self.assertEqual(obtido, esperado)

    def test_execstart_neutralizado(self):
        for nome in (
            "rust-server-mqtt-lab-8884.service",
            "rust-server-mqtt-tls-monitor.service",
        ):
            with self.subTest(nome=nome):
                conteudo = (
                    BASE / f"{nome}.example"
                ).read_text()

                self.assertIn(
                    "ExecStart=/usr/bin/false",
                    conteudo,
                )

    def test_sem_material_sensivel(self):
        padroes = (
            r"-----BEGIN .*PRIVATE KEY-----",
            r"(?im)^\s*(password|token|secret)\s*=",
            r"(?im)^\s*(Environment|EnvironmentFile|"
            r"LoadCredential|SetCredential)\s*=",
        )

        for nome in MODELOS:
            with self.subTest(nome=nome):
                conteudo = (
                    BASE / f"{nome}.example"
                ).read_text()

                for padrao in padroes:
                    self.assertIsNone(
                        re.search(padrao, conteudo),
                    )

    def test_sintaxe_systemd(self):
        ferramenta = shutil.which("systemd-analyze")
        self.assertIsNotNone(
            ferramenta,
            "systemd-analyze nao encontrado",
        )

        with tempfile.TemporaryDirectory(
            prefix="rust-server-dr05-ci-"
        ) as tmp:
            pasta = Path(tmp)

            arquivos = []

            for nome in MODELOS:
                origem = BASE / f"{nome}.example"
                destino = pasta / nome
                destino.write_bytes(origem.read_bytes())
                arquivos.append(str(destino))

            resultado = subprocess.run(
                [ferramenta, "verify", *arquivos],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(
                resultado.returncode,
                0,
                resultado.stdout + resultado.stderr,
            )


if __name__ == "__main__":
    unittest.main()
