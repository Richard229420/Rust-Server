#!/usr/bin/env python3
"""Testes offline sem rede, MQTT, restauracao, Git de escrita ou credenciais."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'scripts'))
import fase8_4_5_5a_preparacao as m

FP = 'a' * 64
DIGEST = 'b' * 64


def context():
    old = m.c.template(FP)
    bridge = next(x for x in old['identities'] if x['username'] == 'bridge')
    bridge['client_id'] = 'rust-server-bridge-local'
    bridge['evidence_kind'] = 'application-code'
    bridge['evidence_ref'] = 'BridgeRustFonteEstatica'
    pending, _ = m.c.validate_model(old, FP)
    assert len(pending) == 21, pending
    return m.c5.Context(FP, tuple(pending), old, {})


class Phase5ATests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'rust-server'
        self.root.mkdir(mode=0o700)
        self.private = self.root / 'phase8-4-5-4c'
        self.private.mkdir(mode=0o700)

    def test_template(self):
        t=m.template(FP,DIGEST)
        self.assertEqual(t['decision'],'NO-GO')
        self.assertEqual(t['phase'],m.PHASE)
        self.assertFalse(t['cutover_authorized'])
        self.assertEqual(t['c_v1_pending'],21)
        self.assertEqual(t['scenario_primary'],'A')
        self.assertEqual(t['scenario_secondary'],'B')
        self.assertEqual(set(t['client_scope']),set(m.c.ACCOUNTS))
        self.assertNotIn('device-sensor01',str(t))
        self.assertEqual(set(t['approvals']),set(m.APPROVAL_KEYS))
        self.assertTrue(all(v is False for v in t['approvals'].values()))
        self.assertTrue(all(v=='pending-independent-evidence' for v in t['requirements'].values()))
        self.assertFalse(t['final_snapshot_captured'])
        self.assertFalse(t['rollback_8883_executed'])
        m.validate(t,FP,DIGEST)

    def test_invalid_fingerprint(self):
        for fp in ('', 'abc', '0'*63, 'G'*64):
            with self.subTest(fp=fp),self.assertRaises(m.Block): m.template(fp,DIGEST)

    def test_invalid_c7_digest(self):
        with self.assertRaises(m.Block): m.template(FP,'bad')

    def test_wrong_snapshot(self):
        with self.assertRaises(m.Block): m.validate(m.template(FP,DIGEST),'c'*64,DIGEST)

    def test_wrong_c7(self):
        with self.assertRaises(m.Block): m.validate(m.template(FP,DIGEST),FP,'c'*64)

    def test_extra_fields(self):
        t=m.template(FP,DIGEST); t['command']='mosquitto'
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_missing_fields(self):
        t=m.template(FP,DIGEST); del t['decision']
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_cutover_true_blocked(self):
        t=m.template(FP,DIGEST); t['cutover_authorized']=True
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_cutover_zero_blocked(self):
        t=m.template(FP,DIGEST); t['cutover_authorized']=0
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_approval_git_ci_true_blocked(self):
        t=m.template(FP,DIGEST); t['approvals']['git_ci']=True
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_approval_security_true_blocked(self):
        t=m.template(FP,DIGEST); t['approvals']['security']=True
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_approval_ops_true_blocked(self):
        t=m.template(FP,DIGEST); t['approvals']['operations']=True
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_approval_zero_blocked(self):
        t=m.template(FP,DIGEST); t['approvals']['security']=0
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_requirements_change_blocked(self):
        t=m.template(FP,DIGEST); t['requirements'][m.REQUIREMENTS[0]]='done'
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_requirement_removed_blocked(self):
        t=m.template(FP,DIGEST); t['requirements'].pop(m.REQUIREMENTS[0])
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_sensor01_addition_blocked(self):
        t=m.template(FP,DIGEST); t['client_scope']['device-sensor01']='verified'
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_fake_client_proof_blocked(self):
        t=m.template(FP,DIGEST); t['client_scope']['bridge']='deployed'
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_fake_final_backup_blocked(self):
        t=m.template(FP,DIGEST); t['final_snapshot_captured']=True
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_fake_rollback_blocked(self):
        t=m.template(FP,DIGEST); t['rollback_8883_executed']=True
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_wrong_scenario_blocked(self):
        t=m.template(FP,DIGEST); t['scenario_primary']='B'
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_wrong_decision_blocked(self):
        t=m.template(FP,DIGEST); t['decision']='GO'
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_wrong_pending_blocked(self):
        t=m.template(FP,DIGEST); t['c_v1_pending']=0
        with self.assertRaises(m.Block): m.validate(t,FP,DIGEST)

    def test_create_private(self):
        m.create_plan(self.root,FP,DIGEST)
        p=self.private/m.FILENAME
        self.assertTrue(p.is_file())
        self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
        self.assertEqual(m.read_plan(self.root,FP,DIGEST),m.template(FP,DIGEST))

    def test_duplicate_create_blocked(self):
        m.create_plan(self.root,FP,DIGEST)
        original=(self.private/m.FILENAME).read_bytes()
        with self.assertRaises(m.Block): m.create_plan(self.root,FP,DIGEST)
        self.assertEqual(original,(self.private/m.FILENAME).read_bytes())

    def test_missing_plan_blocked(self):
        with self.assertRaises(m.Block): m.read_plan(self.root,FP,DIGEST)

    def test_invalid_plan_json_blocked(self):
        p=self.private/m.FILENAME; p.write_text('not-json'); p.chmod(0o600)
        with self.assertRaises(m.Block): m.read_plan(self.root,FP,DIGEST)

    def test_link_blocked(self):
        target=self.root/'source.json'; target.write_text('{}'); target.chmod(0o600)
        (self.private/m.FILENAME).symlink_to(target)
        with self.assertRaises(m.Block): m.read_plan(self.root,FP,DIGEST)
        with self.assertRaises(m.Block): m.create_plan(self.root,FP,DIGEST)

    def test_hardlink_blocked(self):
        m.create_plan(self.root,FP,DIGEST)
        os.link(self.private/m.FILENAME,self.root/'copy.json')
        with self.assertRaises(m.Block): m.read_plan(self.root,FP,DIGEST)

    def test_public_mode_blocked(self):
        m.create_plan(self.root,FP,DIGEST)
        (self.private/m.FILENAME).chmod(0o644)
        with self.assertRaises(m.Block): m.read_plan(self.root,FP,DIGEST)

    def test_bad_dir_blocked(self):
        self.private.chmod(0o755)
        with self.assertRaises(m.Block): m.create_plan(self.root,FP,DIGEST)
        self.private.chmod(0o700)

    def test_port_listeners_ipv4_ipv6(self):
        proc=Path(self.tmp.name)/'proc';proc.mkdir()
        (proc/'tcp').write_text('  sl  local_address rem_address st\n 0: 0100007F:22B3 00000000:0000 0A\n 1: 0100007F:22B4 00000000:0000 01\n')
        (proc/'tcp6').write_text('  sl  local_address rem_address st\n 0: 0000000000000000:22BF 00000000:0000 0A\n')
        result=m.listener_ports(proc)
        self.assertEqual(result[8883],1)
        self.assertEqual(result[8884],0)
        self.assertEqual(result[8895],1)
        self.assertEqual(result[8896],0)

    def test_port_unavailable_not_empty(self):
        self.assertIsNone(m.listener_ports(Path(self.tmp.name)/'missing'))
        self.assertIn('NAO CONFIRMADO',m.ports_report(None)[0])

    def test_port_invalid_header(self):
        proc=Path(self.tmp.name)/'proc';proc.mkdir()
        (proc/'tcp').write_text('bad\n')
        (proc/'tcp6').write_text('local_address st\n')
        with self.assertRaises(m.Block): m.listener_ports(proc)

    def test_listener_report(self):
        observed={p:0 for p in m.PORTS};observed[8883]=1
        report='\n'.join(m.ports_report(observed))
        self.assertIn('PORTA 8883: LISTENER TCP DETECTADO',report)
        self.assertIn('PORTA 8884: SEM LISTENER TCP',report)
        self.assertNotIn('0100007F',report)

    def test_listener_invalid_data(self):
        with self.assertRaises(m.Block):m.ports_report({p:False for p in m.PORTS})

    def test_summary_no_go(self):
        summary=m.safe_status(context(), {p:0 for p in m.PORTS})
        self.assertIn('NO-GO',summary)
        self.assertIn('21 (lab=6, bridge=3, device-sensor02=6, operacionais=6)',summary)
        self.assertIn('8883 NAO AUTORIZADO',summary)

    def test_plan_has_required_actions(self):
        output=m.safe_plan()
        for phrase in ('BRIDGE','B: laboratorio','ROLLBACK','Seguranca','CI','snapshot FINAL'):
            # case insensitive because instructions are explanatory
            if phrase=='snapshot FINAL':
                self.assertIn('snapshot FINAL',output)
            else:
                self.assertIn(phrase.lower(),output.lower())
        self.assertIn('NO-GO',output)

    def test_preflight_mock(self):
        with patch.object(m,'verified_context',return_value=(context(), {}, DIGEST)), \
             patch.object(m,'listener_ports',return_value={p:0 for p in m.PORTS}):
            out=io.StringIO()
            with redirect_stdout(out): ret=m.main(['preflight','--snapshot','/tmp/test'])
        self.assertEqual(ret,0)
        self.assertIn('NO-GO',out.getvalue())

    def test_plano_mock(self):
        with patch.object(m,'verified_context',return_value=(context(), {}, DIGEST)):
            out=io.StringIO()
            with redirect_stdout(out): ret=m.main(['plano','--snapshot','/tmp/test'])
        self.assertEqual(ret,0)
        self.assertIn('NAO EXECUTAR AGORA',out.getvalue())

    def test_criar_mock(self):
        with patch.object(m,'verified_context',return_value=(context(), {}, DIGEST)), \
             patch.object(m,'create_plan') as create:
            out=io.StringIO()
            with redirect_stdout(out): ret=m.main(['criar','--snapshot','/tmp/test'])
        self.assertEqual(ret,0)
        create.assert_called_once()
        self.assertIn('NO-GO',out.getvalue())

    def test_avaliar_mock(self):
        with patch.object(m,'verified_context',return_value=(context(), {}, DIGEST)), \
             patch.object(m,'read_plan',return_value=m.template(FP,DIGEST)), \
             patch.object(m,'listener_ports',return_value={p:0 for p in m.PORTS}):
            out=io.StringIO()
            with redirect_stdout(out): ret=m.main(['avaliar','--snapshot','/tmp/test'])
        self.assertEqual(ret,3)
        self.assertIn('NO-GO',out.getvalue())

    def test_baseline_failure_blocks(self):
        with patch.object(m,'verified_context',side_effect=m.Block('unexpected secret')):
            err=io.StringIO()
            with redirect_stderr(err): ret=m.main(['criar','--snapshot','/tmp/test'])
        self.assertEqual(ret,2)
        self.assertNotIn('unexpected secret',err.getvalue())
        self.assertIn('NAO AUTORIZADO',err.getvalue())

    def test_pending_count_mismatch_blocks(self):
        ctx=context()
        ctx=m.c5.Context(ctx.fingerprint,tuple(ctx.pending[:-1]),ctx.legacy,ctx.classification)
        with patch.object(m.c7,'verified_context',return_value=(ctx,{})):
            with self.assertRaises(m.Block): m.verified_context(Path('/a'),Path('/b'),Path('/c'),Path('/d'),Path('/e'))

    def test_c7_approved_gates_block(self):
        collection={'c_v1_pending':21,'cutover_authorized':False,'external_approvals':{'security':True}}
        with patch.object(m.c7,'verified_context',return_value=(context(),{})), \
             patch.object(m.c7,'read_collection',return_value=collection), \
             patch.object(m.c7,'validate',return_value=None):
            with self.assertRaises(m.Block):m.verified_context(Path('/a'),Path('/b'),Path('/c'),Path('/d'),Path('/e'))

    def test_missing_c7_blocks(self):
        with patch.object(m.os,'geteuid',return_value=1000), \
             patch.object(m.c7,'verified_context',return_value=(context(),{})), \
             patch.object(m.c7,'read_collection',side_effect=m.c7.Block('missing')):
            with self.assertRaises(m.c7.Block):m.verified_context(Path('/a'),Path('/b'),Path('/c'),Path('/d'),Path('/e'))

    def test_no_mqtt_writes_in_source(self):
        source=Path(m.__file__).read_text()
        import ast
        tree=ast.parse(source)
        called=[]
        for node in ast.walk(tree):
            if isinstance(node,ast.Call):
                try: called.append(ast.unparse(node.func))
                except (ValueError,TypeError): pass
        for forbidden in ('subprocess.run', 'subprocess.Popen', 'os.system',
                          'socket.connect', 'os.execv', 'os.kill'):
            self.assertNotIn(forbidden,called)

    def test_only_one_write_action(self):
        self.assertEqual(set(m.ACTIONS),{'preflight','plano','criar','avaliar'})
        self.assertEqual(m.FILENAME,'preparacao-corte-8455a.json')

if __name__=='__main__':
    unittest.main(verbosity=2)
