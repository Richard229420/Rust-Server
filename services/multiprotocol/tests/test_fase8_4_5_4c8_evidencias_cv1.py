#!/usr/bin/env python3
"""Testes isolados (stdlib) para o indice documental C.8."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SRC = Path(__file__).resolve().parents[1] / 'scripts/fase8_4_5_4c8_evidencias_cv1.py'
spec = importlib.util.spec_from_file_location('fase8_4_5_4c8', SRC)
c8 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c8)

class C8Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='rust-c8-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.private = self.root / 'private'
        self.private.mkdir(mode=0o700)
        self.state = self.private / 'c8.json'
        self.c7 = self.private / 'c7.json'
        self.c7.write_text('{"source":"C.7 passive"}')
        self.c7.chmod(0o600)
        self.snap = self.private / 'snapshot'
        self.snap.mkdir()
        self.initargs = ['--state', str(self.state), 'iniciar', '--snapshot', str(self.snap), '--c7', str(self.c7)]

    def cmd(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            # O fixture nao inclui o C.7 real: isolar so testes da C.8,
            # e exercitar rejeicao de drift em testes separados.
            with patch.object(c8, 'require_live_c7', return_value=None):
                rc = c8.main(['--state', str(self.state), *args])
        return rc, out.getvalue(), err.getvalue()

    def init(self):
        rc, out, err = self.cmd('iniciar','--snapshot',str(self.snap),'--c7',str(self.c7))
        self.assertEqual(rc, 0, err)
        return out

    def test_exact_21_and_category_counts(self):
        self.assertEqual(len(c8.REQUIREMENTS), 21)
        self.assertEqual(dict(__import__('collections').Counter(x[1] for x in c8.REQUIREMENTS)), {'lab':6, 'bridge':3,'device-sensor02':6,'operacionais':6})
        self.assertFalse(any('sensor01' in x[0].lower() for x in c8.REQUIREMENTS))

    def test_init_private_and_block_double_init(self):
        self.init()
        self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.private.stat().st_mode), 0o700)
        raw = self.state.read_bytes()
        rc, _, _ = self.cmd('iniciar','--snapshot',str(self.snap),'--c7',str(self.c7))
        self.assertEqual(rc, 2)
        self.assertEqual(raw,self.state.read_bytes())

    def test_empty_status_explicitly_blocks_cut(self):
        self.init()
        rc,out,err = self.cmd('status')
        self.assertEqual(rc,0,err)
        self.assertIn('21 pendencias originais',out)
        self.assertIn('CORTE 8883 NAO AUTORIZADO',out)
        self.assertIn('lab: 0/6',out)

    def test_register_only_opaque_metadata_never_grants(self):
        self.init()
        rc,out,err = self.cmd('registrar','--item','BRI-01','--referencia','EV-A-REDIGIDA00001','--sha256','b'*64,'--tipo','inventario-redigido')
        self.assertEqual(rc,0,err)
        obj=json.loads(self.state.read_text())
        self.assertEqual(obj['evidence'][0]['review'],'pending-independent-review')
        self.assertEqual(obj['approval'],'NOT_GRANTED')
        self.assertEqual(obj['cutover_8883'],'FORBIDDEN')
        self.assertNotIn('EV-A-',self.cmd('status')[1])
        self.assertNotIn('b'*64,self.cmd('status')[1])

    def test_reject_duplicate(self):
        self.init()
        args=('registrar','--item','LAB-01','--referencia','EV-A-ABCDEF12345','--sha256','a'*64,'--tipo','runbook-redigido')
        self.assertEqual(self.cmd(*args)[0],0)
        self.assertEqual(self.cmd(*args)[0],2)
        self.assertEqual(len(json.loads(self.state.read_text())['evidence']),1)

    def test_reject_secret_like_reference_and_invalid_digest(self):
        self.init()
        self.assertEqual(self.cmd('registrar','--item','LAB-01','--referencia','/tmp/senha-real','--sha256','b'*64,'--tipo','runbook-redigido')[0],2)
        self.assertEqual(self.cmd('registrar','--item','LAB-01','--referencia','EV-A-ABCDEF12345','--sha256','not-a-hash','--tipo','runbook-redigido')[0],2)

    def test_reject_unsupported_scenario_or_approval(self):
        self.init()
        obj=json.loads(self.state.read_text())
        obj['scenario']='B'
        self.state.write_text(json.dumps(obj))
        self.assertEqual(self.cmd('verificar')[0],2)
        obj['scenario']='A';obj['approval']='APPROVED'
        self.state.write_text(json.dumps(obj))
        self.assertEqual(self.cmd('status')[0],2)

    def test_reject_changed_c7(self):
        self.init()
        self.c7.write_text('{"source":"changed"}')
        self.assertEqual(self.cmd('verificar')[0],2)

    def test_reject_insecure_mode(self):
        self.init()
        self.state.chmod(0o644)
        self.assertEqual(self.cmd('status')[0],2)

    def test_reject_state_symlink(self):
        self.init()
        real = self.private/'real.json'
        self.state.rename(real)
        self.state.symlink_to(real)
        self.assertEqual(self.cmd('status')[0],2)

    def test_reject_hardlink(self):
        self.init()
        os.link(self.state,self.private/'alias.json')
        self.assertEqual(self.cmd('status')[0],2)

    def test_roteiro_all_and_no_client_credentials(self):
        rc,out,err = self.cmd('roteiro')
        self.assertEqual(rc,0,err)
        self.assertEqual(sum(line.startswith(('LAB-','BRI-','SNS-','OPS-')) for line in out.splitlines()),21)
        self.assertIn('CORTE 8883 NAO AUTORIZADO',out)

    def test_no_mqtt_network_or_git_in_code(self):
        txt = SRC.read_text()
        for forbidden in ('mosquitto_pub','mosquitto_sub','socket.connect','subprocess.run','os.system(', 'git push', 'systemctl start'):
            self.assertNotIn(forbidden,txt)

    def test_c7_not_modified_after_register(self):
        baseline = self.c7.read_bytes()
        self.init()
        self.assertEqual(self.cmd('registrar','--item','OPS-05','--referencia','EV-A-ABCDEF12345','--sha256','f'*64,'--tipo','deliberacao-independente-redigida')[0],0)
        self.assertEqual(self.c7.read_bytes(),baseline)

    def test_invalid_reuse_different_hash(self):
        self.init()
        r = ('--referencia','EV-A-ABCDEF12345','--tipo','inventario-redigido')
        self.assertEqual(self.cmd('registrar','--item','LAB-01',*r,'--sha256','1'*64)[0],0)
        self.assertEqual(self.cmd('registrar','--item','LAB-02',*r,'--sha256','2'*64)[0],2)


    def test_c7_drift_blocks_verify_and_register(self):
        self.init()
        original = self.state.read_bytes()
        with patch.object(c8, 'require_live_c7', side_effect=ValueError('historico divergente')):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = c8.main(['--state', str(self.state), 'verificar'])
            self.assertEqual(rc, 2)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                rc = c8.main(['--state', str(self.state), 'registrar','--item','BRI-01',
                    '--referencia','EV-A-REDIGIDA00001','--sha256','f'*64,'--tipo','inventario-redigido'])
            self.assertEqual(rc, 2)
        self.assertEqual(self.state.read_bytes(), original)

    def test_c7_drift_blocks_new_index(self):
        original = self.c7.read_bytes()
        with patch.object(c8, 'require_live_c7', side_effect=ValueError('historico divergente')):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = c8.main(self.initargs)
            self.assertEqual(rc, 2)
            self.assertFalse(self.state.exists())
        self.assertEqual(self.c7.read_bytes(), original)

    def test_status_with_c7_drift_never_claims_current_validity(self):
        self.init()
        with patch.object(c8, 'require_live_c7', side_effect=ValueError('historico divergente')):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = c8.main(['--state', str(self.state), 'status'])
            self.assertEqual(rc, 2)
            self.assertIn('BLOQUEADO: linha de base C.7', out.getvalue())
            self.assertIn('21 pendencias', out.getvalue())

    def test_real_c7_missing_is_fail_closed(self):
        self.init()
        with patch.object(c8, '__file__', str(self.root / 'inexistente' / 'c8.py')):
            with self.assertRaisesRegex(ValueError, 'C.7 ausente'):
                c8.require_live_c7(self.snap)

    def test_real_c7_main_zero_args_pass_and_reject(self):
        fake = self.root / 'audit-c7'
        fake.mkdir()
        src = fake / 'fase8_4_5_4c7_coleta_evidencias.py'
        with patch.object(c8, '__file__', str(fake / 'fase8_4_5_4c8_evidencias_cv1.py')):
            src.write_text('def main():\n    return 0\n')
            c8.require_live_c7(self.snap)
            src.write_text('def main():\n    return 2\n')
            with self.assertRaisesRegex(ValueError, 'C.7 nao validou'):
                c8.require_live_c7(self.snap)

    def test_real_c7_main_argv_pass_and_reject(self):
        fake = self.root / 'audit-c7'
        fake.mkdir()
        src = fake / 'fase8_4_5_4c7_coleta_evidencias.py'
        src.write_text('def main(argv):\n'
                       '    assert argv[0] == "verificar"\n'
                       '    assert argv[1] == "--snapshot"\n'
                       '    return 0\n')
        with patch.object(c8, '__file__', str(fake / 'fase8_4_5_4c8_evidencias_cv1.py')):
            c8.require_live_c7(self.snap)

if __name__=='__main__':
    unittest.main(verbosity=2)
