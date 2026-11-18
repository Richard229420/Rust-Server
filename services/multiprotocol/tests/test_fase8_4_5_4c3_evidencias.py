#!/usr/bin/env python3
"""Testes offline da 8.4.5.4-C.3, sem brokers ou snapshot real."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fase8_4_5_4c3_evidencias as m
import fase8_4_5_4c_prontidao_corte as c

FP = hashlib.sha256(b'fake-manifest').hexdigest()


class Tests(unittest.TestCase):
    def fresh(self):
        return c.template(FP)

    def test_model_fresh_24(self):
        pending, _ = c.validate_model(self.fresh(), FP)
        self.assertEqual(len(pending), 24)

    def test_bridge_only_three_fields(self):
        old = self.fresh()
        result = m.reviewed_model(old, FP)
        changed = result['identities'][1]
        self.assertEqual(changed['client_id'], m.BRIDGE_ID)
        self.assertEqual(changed['evidence_kind'], 'application-code')
        self.assertEqual(changed['evidence_ref'], m.BRIDGE_REFERENCE)
        self.assertFalse(changed['client_id_confirmado'])
        self.assertFalse(changed['cliente_suporta_troca_credencial'])
        self.assertFalse(changed['retorno_credencial_legada_planejado'])
        self.assertEqual(result['identities'][0], old['identities'][0])
        self.assertEqual(result['identities'][2], old['identities'][2])
        self.assertEqual(result['readiness'], old['readiness'])
        self.assertEqual(old['identities'][1]['client_id'], '')
        self.assertFalse(result['cutover_authorized'])

    def test_count_21(self):
        result = m.reviewed_model(self.fresh(), FP)
        pending, _ = c.validate_model(result, FP)
        self.assertEqual(len(pending), 21)
        self.assertEqual(m.cons.pending_counts(pending),
                         {'lab': 6, 'bridge': 3, 'device-sensor02': 6, 'operacionais': 6})

    def test_idempotent_model(self):
        first = m.reviewed_model(self.fresh(), FP)
        self.assertEqual(first, m.reviewed_model(first, FP))

    def test_reject_different_bridge_id(self):
        old = self.fresh()
        old['identities'][1]['client_id'] = 'other-id'
        with self.assertRaises(m.Block):
            m.reviewed_model(old, FP)

    def test_reject_different_evidence(self):
        old = self.fresh()
        old['identities'][1]['evidence_ref'] = 'another-evidence'
        with self.assertRaises(m.Block):
            m.reviewed_model(old, FP)

    def test_reject_claim_runtime_confirmation(self):
        old = self.fresh()
        old['identities'][1].update({'client_id':m.BRIDGE_ID,
                                    'evidence_kind':'application-code',
                                    'evidence_ref':m.BRIDGE_REFERENCE,
                                    'client_id_confirmado':True})
        with self.assertRaises(m.Block): m.reviewed_model(old, FP)

    def test_reject_bad_snapshot(self):
        with self.assertRaises(c.Block): m.reviewed_model(self.fresh(), 'invalid')

    def test_no_auto_lab_id(self):
        updated = m.reviewed_model(self.fresh(), FP)
        self.assertEqual(updated['identities'][0]['client_id'], '')

    def test_revoked_not_created(self):
        updated = m.reviewed_model(self.fresh(), FP)
        self.assertNotIn('device-sensor01', [x['username'] for x in updated['identities']])

    def test_file_permissions(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'cadastro.json'
            data = ("{}\n").encode()
            path.write_bytes(data)
            os.chmod(path, 0o600)
            raw, st = m.secured_original(path)
            self.assertEqual(raw, data)
            self.assertTrue(m.atomic_save_model(path, raw, st, {'updated':True}))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.read_text(), '{\n  "updated": true\n}\n')

    def test_file_link_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'a'
            path.write_text('x')
            os.chmod(path, 0o600)
            link = Path(d)/'b'
            link.symlink_to(path)
            with self.assertRaises(m.Block): m.secured_original(link)

    def test_file_hardlink_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'a'
            path.write_text('x')
            os.chmod(path, 0o600)
            os.link(path, Path(d)/'b')
            with self.assertRaises(m.Block): m.secured_original(path)

    def test_file_public_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'a'
            path.write_text('x')
            os.chmod(path, 0o644)
            with self.assertRaises(m.Block): m.secured_original(path)

    def test_refuse_changed_original(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'a'
            path.write_bytes(b'one')
            os.chmod(path,0o600)
            raw,st=m.secured_original(path)
            path.write_bytes(b'two')
            with self.assertRaises(m.Block):
                m.atomic_save_model(path,raw,st,{'ok':True})
            self.assertEqual(path.read_bytes(),b'two')

    def test_no_password_in_report(self):
        out=io.StringIO()
        with redirect_stdout(out): m.summarize(['Client ID real nao registrado: lab'])
        self.assertIn('CORTE 8883 NAO AUTORIZADO',out.getvalue())
        self.assertNotIn('password',out.getvalue().lower())

    def test_roteiro_maintains_cut_block(self):
        out=io.StringIO()
        with redirect_stdout(out): m.instructions()
        self.assertIn('CORTE',out.getvalue())
        self.assertNotIn('senha123',out.getvalue())

    def test_no_mqtt_calls(self):
        source=Path(m.__file__).read_text()
        for text in ('mosquitto_pub', 'mosquitto_ctrl', 'mosquitto_sub',
                     'subprocess.Popen', 'socket.create_connection', 'cargo build',
                     'git checkout', 'git push', 'git commit'):
            self.assertNotIn(text, source)

    @patch.object(m, 'verify_bridge_source')
    @patch.object(c, 'baseline', return_value=(FP, {}))
    @patch.object(c, 'verify_branch')
    def test_cli_only_reads_on_audit(self, branch, baseline, source):
        model = self.fresh()
        with patch.object(c, 'private_folder', return_value=Path('/safe')) as folder, \
             patch.object(m, 'secured_original', return_value=(b'{}', object())), \
             patch.object(c, 'load_model', return_value=model), \
             patch.object(m, 'atomic_save_model') as writer, \
             redirect_stdout(io.StringIO()):
            code=m.main(['auditar', '--snapshot', '/ficticio'])
        self.assertEqual(code,0)
        writer.assert_not_called()
        branch.assert_called_once()
        baseline.assert_called_once()
        source.assert_called_once()
        folder.assert_called_once()


if __name__ == '__main__':
    unittest.main(verbosity=2)
