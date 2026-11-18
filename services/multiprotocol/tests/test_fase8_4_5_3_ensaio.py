#!/usr/bin/env python3
"""Regression offline 8.4.5.3: synthetic fixtures and mocked broker; no real ports."""
from __future__ import annotations

from contextlib import contextmanager, redirect_stdout
import io
import os
from pathlib import Path, PurePosixPath
import sys
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / 'scripts'
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fase8_4_5_3_ensaio as impl
import fase8_4_5_2_preparar as p2
import test_fase8_4_5_2_preparar as fixtures

SECRET = 'FAKE_PASSWORD_' + 'X'*40


class Phase53Tests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.PreparationTests('test_preparar_snapshot_privado')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.home = fixture.home
        self.project = fixture.project
        self.root = fixture.root
        self.plugin = fixture.plugin
        self.dest = fixture.dest
        for user, client in [('device-sensor01','lab84-sensor01'),
                             ('device-sensor02','lab84-sensor02'), ('lab84-bridge','lab84-bridge')]:
            path = fixture.lab / 'clients' / (user + '.opts')
            fixtures.put(path, f'-h localhost\n-p 8884\n--cafile {fixture.lab}/pki/ca.crt\n'
                               f'-u {user}\n-P {SECRET}\n-i {client}\n')
        fixtures.put(self.root/'mqtt-lab.token', 'L'*40)
        fixtures.put(self.root/'mqtt-bridge.token', 'B'*40)
        self.snapshot = fixture.prepare()

    def scratch(self):
        p = self.home / ('scratch-' + str(len(list(self.home.glob('scratch-*')))))
        p.mkdir(mode=0o700)
        return p

    def stage(self):
        work = self.scratch()
        impl.restore_files(self.snapshot, work)
        return work

    def test_restaura_exatamente_20_sem_alterar_originais(self):
        before = (self.root/'mqtt-bridge.token').read_bytes()
        work = self.stage()
        files = [work/'files'/k for k in p2.SPECS]
        self.assertEqual(len(files), 20)
        self.assertTrue(all(x.is_file() and (x.stat().st_mode & 0o777) == 0o600 for x in files))
        self.assertEqual((self.root/'mqtt-bridge.token').read_bytes(), before)
        self.assertNotEqual(files[0].stat().st_ino, (self.snapshot/'files'/next(iter(p2.SPECS))).stat().st_ino)

    def test_candidate_referencia_somente_scratch(self):
        work = self.stage()
        config = impl.build_candidate(self.snapshot, work, self.plugin)
        text = config.read_text()
        self.assertIn('listener 8895 127.0.0.1', text)
        self.assertIn(str(work/'candidate/dynamic-security.json'), text)
        self.assertNotIn(str(self.snapshot), text)
        self.assertNotIn('listener 8883', text)
        self.assertNotIn('listener 8884', text)
        self.assertNotIn(SECRET, text)
        self.assertEqual((work/'candidate/dynamic-security.json').read_bytes(),
                         (self.snapshot/'files/lab/dynamic-security.json').read_bytes())
        self.assertEqual(p2.verify(self.snapshot,self.plugin), 20)

    def test_rollback_referencia_somente_copias(self):
        work = self.stage()
        text = impl.build_rollback(work).read_text()
        self.assertIn('listener 8896 127.0.0.1', text)
        self.assertIn('allow_anonymous false', text)
        self.assertIn(f'password_file {work}/files/legacy/passwords', text)
        self.assertIn(f'acl_file {work}/files/legacy/acl', text)
        self.assertNotIn('plugin_use', text)
        self.assertNotIn('listener 8883', text)
        self.assertNotIn('listener 8884', text)
        self.assertNotIn(str(self.snapshot), text)

    def test_lab_opts_apenas_remapeia_porta_e_ca(self):
        work=self.stage()
        result=impl.parse_lab_options(work,'device-sensor02',8895).decode()
        self.assertIn('-p 8895\n',result)
        self.assertIn(f'--cafile {work}/files/legacy/certs/ca.crt',result)
        self.assertIn('-u device-sensor02',result)
        self.assertIn('-i lab84-sensor02',result)
        self.assertIn(SECRET,result)
        self.assertNotIn('8884',result)

    def test_lab_opts_rejeita_id_falsificado(self):
        work=self.stage()
        path=work/'files/lab/clients/device-sensor02.opts'
        path.write_text(path.read_text().replace('lab84-sensor02','lab84-sensor01'))
        with self.assertRaises(impl.Block):
            impl.parse_lab_options(work,'device-sensor02',8895)

    def test_lab_opts_rejeita_injecao_de_opcao(self):
        work=self.stage()
        path=work/'files/lab/clients/device-sensor02.opts'
        path.write_text(path.read_text() + '--insecure xyz\n')
        with self.assertRaises(impl.Block):
            impl.parse_lab_options(work,'device-sensor02',8895)

    def test_lab_opts_rejeita_usuario_desconhecido(self):
        with self.assertRaises(impl.Block):
            impl.parse_lab_options(self.scratch(),'lab84-admin',8895)

    def test_lab_opts_rejeita_ca_de_outro_ambiente(self):
        work=self.stage()
        path=work/'files/lab/clients/device-sensor02.opts'
        path.write_text(path.read_text().replace('/pki/ca.crt','/pki/other.crt'))
        with self.assertRaises(impl.Block):
            impl.parse_lab_options(work,'device-sensor02',8895)

    def test_legacy_options_tem_token_privado_sem_argv(self):
        work=self.stage()
        opts=impl.legacy_options(work,'lab',8896).decode()
        self.assertIn('-u lab\n',opts)
        self.assertIn('-p 8896\n',opts)
        self.assertIn('-P ' + 'L'*40,opts)
        self.assertNotIn('8883', opts)

    def test_legacy_options_invalido_bloqueia(self):
        work=self.stage()
        path=work/'files/legacy/mqtt-lab.token'
        path.write_text('bad\npassword')
        with self.assertRaises(impl.Block):
            impl.legacy_options(work,'lab',8896)

    def test_legacy_user_nao_previsto(self):
        with self.assertRaises(impl.Block):
            impl.legacy_options(self.scratch(),'sensor01',8896)

    def test_arquivo_de_origem_alterado_bloqueia_snapshot_antigo(self):
        impl.assert_origins_match(self.snapshot,self.project,self.root)
        (self.root/'mosquitto/acl').write_text('ALTERACAO NA ORIGEM')
        with self.assertRaisesRegex(impl.Block,'desatualizado'):
            impl.assert_origins_match(self.snapshot,self.project,self.root)

    def test_token_de_origem_alterado_bloqueia_snapshot_antigo(self):
        (self.root/'mqtt-bridge.token').write_text('Z'*40)
        with self.assertRaises(impl.Block):
            impl.assert_origins_match(self.snapshot,self.project,self.root)

    def test_snapshot_corrompido_bloqueia_preflight(self):
        (self.snapshot/'files/legacy/acl').write_text('wrong')
        with self.assertRaises(p2.Block):
            p2.verify(self.snapshot,self.plugin)

    def test_snapshot_symlink_rejeitado(self):
        name=self.snapshot/'files/legacy/acl'
        name.unlink()
        name.symlink_to(self.root/'mosquitto/acl')
        with self.assertRaises(p2.Block):
            p2.verify(self.snapshot,self.plugin)

    def test_portas_reais_nunca_em_configs(self):
        work=self.stage()
        cfg=impl.build_candidate(self.snapshot,work,self.plugin).read_bytes()
        rollback=impl.build_rollback(work).read_bytes()
        for fragment in (b'listener 8883', b'listener 8884'):
            self.assertNotIn(fragment,cfg)
            self.assertNotIn(fragment,rollback)

    def test_success_mocked_flow_cleanup(self):
        begun=[]
        @contextmanager
        def fake_broker(_cfg, port):
            begun.append(port)
            yield
        with (patch.object(impl,'prereq'),patch.object(impl,'probe_original', return_value=('parado','parado')),
              patch.object(impl,'config_check'),patch.object(impl,'broker',side_effect=fake_broker),
              patch.object(impl,'available',return_value=True),
              patch.object(impl,'mqtt_delivery',return_value=True) as delivery,
              patch.object(impl,'mqtt_denied',return_value=True) as denied,
              redirect_stdout(io.StringIO()) as output):
            impl.run(self.snapshot,self.dest,self.project,self.root,self.plugin)
        self.assertEqual(begun,[8895,8896])
        self.assertEqual(delivery.call_count,2)
        denied.assert_called_once()
        self.assertIn('ENSAIO 8.4.5.3 APROVADO',output.getvalue())
        self.assertNotIn(SECRET,output.getvalue())
        self.assertEqual([p.name for p in self.dest.iterdir() if p.name.startswith('.ensaio-')],[])
        self.assertEqual(p2.verify(self.snapshot,self.plugin),20)

    def test_failure_mocked_candidate_cleans_up_without_rollback(self):
        begun=[]
        @contextmanager
        def fake_broker(_cfg,port):
            begun.append(port)
            yield
        with (patch.object(impl,'prereq'),patch.object(impl,'probe_original',return_value=('parado','parado')),
              patch.object(impl,'config_check'),patch.object(impl,'broker',side_effect=fake_broker),
              patch.object(impl,'available',return_value=True),
              patch.object(impl,'mqtt_delivery',return_value=False),
              redirect_stdout(io.StringIO())):
            with self.assertRaises(impl.Block):
                impl.run(self.snapshot,self.dest,self.project,self.root,self.plugin)
        self.assertEqual(begun,[8895])
        self.assertEqual([p.name for p in self.dest.iterdir() if p.name.startswith('.ensaio-')],[])

    def test_failure_mocked_revoked_rejected_blocks_rollback(self):
        begun=[]
        @contextmanager
        def fake_broker(_cfg,port):
            begun.append(port)
            yield
        with (patch.object(impl,'prereq'),patch.object(impl,'probe_original',return_value=('parado','parado')),
              patch.object(impl,'config_check'),patch.object(impl,'broker',side_effect=fake_broker),
              patch.object(impl,'available',return_value=True),
              patch.object(impl,'mqtt_delivery',return_value=True),
              patch.object(impl,'mqtt_denied',return_value=False),
              redirect_stdout(io.StringIO())):
            with self.assertRaises(impl.Block):
                impl.run(self.snapshot,self.dest,self.project,self.root,self.plugin)
        self.assertEqual(begun,[8895])

    def test_broker_rejeita_porta_principal(self):
        with self.assertRaises(impl.Block):
            with impl.broker(self.project/'no',8883): pass

    def test_ports_occupied_block(self):
        with patch.object(impl,'available',side_effect=[False,True]):
            with self.assertRaises(impl.Block):
                impl.require(impl.available(8895) and impl.available(8896),'porta ocupada')

    def test_options_file_0600(self):
        work=self.scratch()
        path=impl.options_file(work,'test', b'-u mock\n-P secret\n')
        self.assertEqual(path.stat().st_mode & 0o777,0o600)

    def test_permissive_snapshot_blocked(self):
        (self.snapshot/'files/legacy/mqtt-lab.token').chmod(0o644)
        with self.assertRaises(p2.Block):
            p2.verify(self.snapshot,self.plugin)

    def test_command_argv_never_contains_password(self):
        work=self.scratch()
        opts=impl.options_file(work,'mock',b'-P SUPERSECRET\n')
        with patch.object(impl.subprocess,'run') as proc:
            proc.return_value.returncode=0
            self.assertTrue(impl.safe_run(['mosquitto_pub','-o',str(opts),'-t','lab/alerts','-m','x']))
            argv=proc.call_args.args[0]
        self.assertNotIn('SUPERSECRET',' '.join(argv))


if __name__=='__main__':
    unittest.main(verbosity=2)
