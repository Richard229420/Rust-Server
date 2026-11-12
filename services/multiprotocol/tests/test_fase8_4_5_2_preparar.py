#!/usr/bin/env python3
"""Offline regression for phase 8.4.5.2: synthetic secrets, never the real brokers."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))
import fase8_4_5_2_preparar as impl
import test_fase8_4_5_1_auditoria as fixtures
put = fixtures.put


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.AuditTests('test_baseline_aceito_sem_autorizacao_de_migracao')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.project = self.fixture.project
        self.root = self.fixture.root
        self.lab = self.fixture.lab
        self.plugin = self.fixture.plugin
        self.home = Path(self.fixture.tmp.name)
        self.dest = self.home / 'server_backups' / 'fase8_4_5_2'
        put(self.root / 'mqtt-bridge.token', 'TEST_TOKEN_SECRET')
        put(self.root / 'mqtt-lab.token', 'TEST_TOKEN_SECRET')
        put(self.lab / 'pki/ca.key', 'TEST_LAB_CA_KEY')
        put(self.lab / 'provisioned.json', '{"phase":"8.4.2","port":8884}')

    def prepare(self):
        return impl.prepare(self.project, self.root, self.plugin, self.dest, self.home)

    def test_preflight_nao_cria_diretorios(self):
        impl.preflight(self.project, self.root, self.plugin, self.dest, self.home)
        self.assertFalse(self.dest.exists())

    def test_arquivos_obrigatorios_exatos(self):
        files = impl.gather(self.project, self.root)
        self.assertEqual(set(files), set(impl.SPECS))
        self.assertEqual(len(files), 20)

    def test_preparar_snapshot_privado(self):
        snap = self.prepare()
        self.assertEqual(impl.verify(snap, self.plugin), 20)
        self.assertEqual(snap.stat().st_mode & 0o777, 0o700)
        self.assertEqual((snap / impl.NAME).stat().st_mode & 0o777, 0o600)
        self.assertEqual((snap/'files/lab/dynamic-security.json').stat().st_mode & 0o777, 0o600)

    def test_simulacao_temporaria_sem_escrever_no_broker(self):
        original = (self.root / 'mosquitto/passwords').read_bytes()
        snap = self.prepare()
        self.assertEqual(impl.simulated_restore(snap, self.plugin), 20)
        self.assertEqual((self.root / 'mosquitto/passwords').read_bytes(), original)
        self.assertEqual([x for x in self.dest.iterdir() if x.name.startswith('.restauracao')], [])

    def test_config_candidata_nao_toca_portas_reais(self):
        snap = self.prepare()
        config = (snap / 'candidate/mosquitto-candidate.conf').read_text()
        self.assertIn('listener 8895 127.0.0.1', config)
        self.assertNotIn('listener 8883', config)
        self.assertNotIn('listener 8884', config)
        self.assertIn(str(snap / 'candidate/dynamic-security.json'), config)
        self.assertEqual((snap/'candidate/dynamic-security.json').read_bytes(),
                         (snap/'files/lab/dynamic-security.json').read_bytes())
        self.assertNotIn('TEST_TOKEN_SECRET', config)

    def test_snapshot_alterado_bloqueia(self):
        snap = self.prepare()
        (snap/'files/legacy/acl').write_bytes(b'MALICIOUS')
        with self.assertRaises(impl.Block):
            impl.verify(snap, self.plugin)

    def test_config_candidata_alterada_bloqueia(self):
        snap = self.prepare()
        p = snap/'candidate/mosquitto-candidate.conf'
        p.write_text(p.read_text().replace('8895', '8883'))
        with self.assertRaises(impl.Block):
            impl.verify(snap, self.plugin)

    def test_estado_candidato_mudou_bloqueia(self):
        snap = self.prepare()
        (snap/'candidate/dynamic-security.json').write_text('{}')
        with self.assertRaises(impl.Block):
            impl.verify(snap, self.plugin)

    def test_manifesto_tamper_bloqueia(self):
        snap = self.prepare()
        manifest = json.loads((snap / impl.NAME).read_text())
        manifest['files'][0]['sha256'] = '0' * 64
        (snap / impl.NAME).write_text(json.dumps(manifest))
        with self.assertRaises(impl.Block):
            impl.verify(snap, self.plugin)

    def test_origem_symlink_bloqueia(self):
        p = self.root/'mqtt-lab.token'
        p.unlink()
        p.symlink_to(self.root/'mqtt-bridge.token')
        with self.assertRaises(impl.Block):
            self.prepare()

    def test_origem_hardlink_bloqueia(self):
        p = self.root/'mqtt-lab.token'
        p.unlink()
        os.link(self.root/'mqtt-bridge.token', p)
        with self.assertRaises(impl.Block):
            self.prepare()

    def test_origem_permissiva_bloqueia(self):
        (self.root/'mqtt-bridge.token').chmod(0o644)
        with self.assertRaises(impl.Block):
            self.prepare()

    def test_acl_insegura_impede_snapshot(self):
        p = self.root / 'mosquitto/acl'
        put(p, p.read_text() + 'topic read #\n')
        with self.assertRaises(impl.Block):
            self.prepare()

    def test_marcador_incompleto_impede_snapshot(self):
        put(self.lab / 'fase8_4_4_state.json', '{"phase":"8.4.4", "stage":"disable-requested"}')
        with self.assertRaises(impl.Block):
            self.prepare()

    def test_armazenamento_dentro_do_git_bloqueia(self):
        with self.assertRaises(impl.Block):
            impl.prepare(self.project, self.root, self.plugin, self.project / 'mybackups', self.home)

    def test_armazenamento_dentro_de_config_privada_bloqueia(self):
        with self.assertRaises(impl.Block):
            impl.prepare(self.project, self.root, self.plugin, self.root / 'mybackups', self.home)

    def test_diretorio_existente_publico_bloqueia(self):
        self.dest.parent.mkdir(mode=0o755)
        self.dest.parent.chmod(0o755)
        with self.assertRaises(impl.Block):
            self.prepare()

    def test_preflight_bloqueia_pai_0755_sem_destino(self):
        self.dest.parent.mkdir(mode=0o755)
        self.dest.parent.chmod(0o755)
        self.assertFalse(self.dest.exists())
        with self.assertRaisesRegex(impl.Block, 'diretorio nao privado'):
            impl.preflight(self.project, self.root, self.plugin, self.dest, self.home)
        self.assertFalse(self.dest.exists())

    def test_preflight_aceita_pai_0700_sem_criar_destino(self):
        self.dest.parent.mkdir(mode=0o700)
        impl.preflight(self.project, self.root, self.plugin, self.dest, self.home)
        self.assertFalse(self.dest.exists())

    def test_symlink_do_destino_bloqueia(self):
        other = self.home/'other'
        other.mkdir(mode=0o700)
        self.dest.parent.mkdir(mode=0o700)
        self.dest.symlink_to(other, target_is_directory=True)
        with self.assertRaises(impl.Block):
            self.prepare()

    def test_chave_privada_ausente_bloqueia(self):
        (self.lab/'pki/ca.key').unlink()
        with self.assertRaises(impl.Block):
            self.prepare()

    def test_dois_snapshots_sem_sobrescrever(self):
        first = self.prepare()
        second = self.prepare()
        self.assertNotEqual(first, second)
        self.assertEqual(impl.verify(first, self.plugin), 20)
        self.assertEqual(impl.verify(second, self.plugin), 20)

    def test_snapshots_sao_exclusivamente_copias(self):
        originals = [self.root/'mosquitto/mosquitto.conf', self.root/'mosquitto/passwords',
                     self.lab/'dynamic-security.json', self.project/'certs/localhost.key']
        before = [(p.stat().st_mtime_ns, p.read_bytes()) for p in originals]
        self.prepare()
        self.assertEqual(before, [(p.stat().st_mtime_ns, p.read_bytes()) for p in originals])

    def test_rejeita_link_em_snapshot(self):
        snap = self.prepare()
        f = snap / 'files/legacy/passwords'
        f.unlink()
        f.symlink_to(self.root/'mosquitto/passwords')
        with self.assertRaises(impl.Block):
            impl.verify(snap, self.plugin)

    def test_rejeita_permissaor_publica_snapshot(self):
        snap = self.prepare()
        (snap/'files/legacy/passwords').chmod(0o644)
        with self.assertRaises(impl.Block):
            impl.verify(snap, self.plugin)

    def test_nao_vaza_segredo_em_excecao(self):
        put(self.lab/'dynamic-security.json', '{"secret":"VERY_PRIVATE"}')
        snap = self.prepare()
        (snap/'files/lab/dynamic-security.json').write_text('VERY_PRIVATE')
        with self.assertRaises(impl.Block) as ctx:
            impl.verify(snap, self.plugin)
        self.assertNotIn('VERY_PRIVATE', str(ctx.exception))


if __name__ == '__main__':
    unittest.main(verbosity=2)
