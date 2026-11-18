#!/usr/bin/env python3
"""Testes OFFLINE C.4; nao iniciam Mosquitto nem usam snapshot real."""
from __future__ import annotations

import copy
from contextlib import redirect_stdout, redirect_stderr
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fase8_4_5_4c4_classificacao as m
import fase8_4_5_4c_prontidao_corte as c
import fase8_4_5_4c3_evidencias as c3

FP = hashlib.sha256(b'c4-fake-snapshot').hexdigest()


class C4Tests(unittest.TestCase):
    def basic(self):
        return m.template(FP)

    def private_fixture(self, root):
        root = Path(root)
        private = root / 'rust-server'
        private.mkdir(mode=0o700)
        (private / 'phase8-4-5-4c').mkdir(mode=0o700)
        return private

    def bridge_legacy(self):
        return c3.reviewed_model(c.template(FP), FP)

    def test_valid_default(self):
        m.validate(self.basic(), FP)

    def test_modes_A_primary_B_secondary(self):
        model = self.basic()
        self.assertEqual(model['scenarios']['A']['role'], 'operational-primary')
        self.assertEqual(model['scenarios']['B']['role'], 'laboratory-secondary')

    def test_lab_A_pending_review(self):
        self.assertEqual(self.basic()['scenarios']['A']['identities']['lab']['client_id_policy'],
                         'security-review-pending')

    def test_lab_B_dynamic_cli(self):
        row = self.basic()['scenarios']['B']['identities']['lab']
        self.assertEqual((row['client_class'], row['client_id_policy']),
                         ('cli-temporary', 'dynamic-cli'))

    def test_fixed_for_bridge_and_sensor_both(self):
        for scenario in m.SCENARIOS:
            for name in ('bridge', 'device-sensor02'):
                record = self.basic()['scenarios'][scenario]['identities'][name]
                self.assertEqual((record['client_class'], record['client_id_policy']),
                                 ('persistent', 'fixed'))

    def test_no_revoked_identity(self):
        for scenario in m.SCENARIOS:
            self.assertEqual(set(self.basic()['scenarios'][scenario]['identities']),
                             set(c.ACCOUNTS))
            self.assertNotIn('device-sensor01', self.basic()['scenarios'][scenario]['identities'])

    def test_no_auto_confirm_or_cut(self):
        d = self.basic()
        self.assertIs(d['cutover_authorized'], False)
        self.assertEqual(d['gates'], {x: False for x in m.GATES})
        for s in m.SCENARIOS:
            for row in d['scenarios'][s]['identities'].values():
                self.assertEqual(row['deployment'], 'unknown')
                self.assertEqual(row['evidence_ref'], '')

    def test_reject_different_snapshot(self):
        with self.assertRaises(m.Block): m.validate(self.basic(), 'x' * 64)

    def test_reject_invalid_fingerprint_in_template(self):
        with self.assertRaises(m.Block): m.template('invalid')

    def test_reject_modified_phase(self):
        d = self.basic()
        d['phase'] = '8.4.5.5'
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_cutover(self):
        d = self.basic()
        d['cutover_authorized'] = True
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_security_gate(self):
        d = self.basic()
        d['gates']['security'] = True
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_git_ci_gate(self):
        d = self.basic()
        d['gates']['git_ci'] = True
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_operational_gate(self):
        d = self.basic()
        d['gates']['operational_readiness'] = True
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_extra_identity(self):
        d = self.basic()
        d['scenarios']['A']['identities']['device-sensor01'] = {}
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_extra_scenario(self):
        d = self.basic()
        d['scenarios']['PRODUCTION'] = {}
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_lab_A_dynamic_without_security_review(self):
        d = self.basic()
        d['scenarios']['A']['identities']['lab']['client_id_policy'] = 'dynamic-cli'
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_lab_B_fixed(self):
        d = self.basic()
        d['scenarios']['B']['identities']['lab']['client_id_policy'] = 'fixed'
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_unregistered_evidence(self):
        d = self.basic()
        d['scenarios']['A']['identities']['bridge']['evidence_ref'] = 'source-ref-001'
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_declared_without_evidence(self):
        d = self.basic()
        d['scenarios']['A']['identities']['bridge']['deployment'] = 'declared-deployed'
        with self.assertRaises(m.Block): m.validate(d, FP)

    def test_reject_secret_reference(self):
        for text in ('Password123', 'secret-1234', 'token-auth123', 'senha-1234',
                     '/home/person/key', '--', 'https://somewhere', 'a'*100):
            self.assertFalse(m.safe_reference(text), text)

    def test_reject_bad_scenario(self):
        with self.assertRaises(m.Block):
            m.update_declaration(self.basic(), FP, scenario='C', identity='lab',
                                 state='declared-deployed', kind='lab-log', reference='LabReport-0123')

    def test_propose_fixed_per_instance_lab_A(self):
        old = self.basic()
        new = m.propose_lab_policy(old, FP, 'fixed-per-instance-proposed')
        self.assertEqual(new['scenarios']['A']['identities']['lab']['client_id_policy'],
                         'fixed-per-instance-proposed')
        self.assertEqual(new['scenarios']['B'], old['scenarios']['B'])
        self.assertFalse(new['gates']['security'])
        self.assertEqual(old, self.basic())

    def test_propose_dynamic_lab_A_without_auto_approval(self):
        new = m.propose_lab_policy(self.basic(), FP, 'dynamic-cli-proposed')
        self.assertFalse(new['gates']['security'])
        self.assertFalse(new['cutover_authorized'])
        m.validate(new, FP)

    def test_propose_lab_A_idempotent(self):
        new = m.propose_lab_policy(self.basic(), FP, 'fixed-per-instance-proposed')
        self.assertEqual(new, m.propose_lab_policy(new, FP, 'fixed-per-instance-proposed'))

    def test_propose_lab_A_conflicting_rejected(self):
        new = m.propose_lab_policy(self.basic(), FP, 'fixed-per-instance-proposed')
        with self.assertRaises(m.Block):
            m.propose_lab_policy(new, FP, 'dynamic-cli-proposed')

    def test_propose_invalid_blocked(self):
        with self.assertRaises(m.Block): m.propose_lab_policy(self.basic(), FP, 'approved')

    def test_declaration_only_one_A(self):
        old = self.basic()
        d = m.update_declaration(old, FP, scenario='A', identity='device-sensor02',
                                 state='declared-deployed', kind='device-config',
                                 reference='DeviceReport-20261103')
        self.assertEqual(d['scenarios']['A']['identities']['device-sensor02']['deployment'],
                         'declared-deployed')
        self.assertEqual(d['scenarios']['B'], old['scenarios']['B'])
        self.assertEqual(d['scenarios']['A']['identities']['bridge'],
                         old['scenarios']['A']['identities']['bridge'])
        self.assertEqual(old, self.basic())
        self.assertFalse(d['cutover_authorized'])
        m.validate(d, FP)

    def test_declaration_lab_B_only(self):
        d = m.update_declaration(self.basic(), FP, scenario='B', identity='lab',
                                 state='declared-not-deployed',
                                 kind='operator-attestation', reference='Attestation-20261103')
        self.assertEqual(d['scenarios']['B']['identities']['lab']['deployment'],
                         'declared-not-deployed')
        self.assertEqual(d['scenarios']['A'], self.basic()['scenarios']['A'])

    def test_declaration_idempotent(self):
        kw = dict(scenario='A', identity='lab', state='declared-deployed',
                  kind='deployment-inventory', reference='Inventory-20261103')
        first = m.update_declaration(self.basic(), FP, **kw)
        self.assertEqual(first, m.update_declaration(first, FP, **kw))

    def test_declaration_conflict_blocked(self):
        first = m.update_declaration(self.basic(), FP, scenario='A', identity='lab',
                                     state='declared-deployed', kind='deployment-inventory',
                                     reference='Inventory-20261103')
        with self.assertRaises(m.Block):
            m.update_declaration(first, FP, scenario='A', identity='lab',
                                 state='declared-not-deployed', kind='operator-attestation',
                                 reference='Claim-20261104')

    def test_declaration_does_not_close_Cv1(self):
        legacy = self.bridge_legacy()
        pending = m.reviewed_legacy(legacy, FP)
        self.assertEqual(len(pending), 21)
        d = m.update_declaration(self.basic(), FP, scenario='A',
                                 identity='device-sensor02', state='declared-deployed',
                                 kind='device-config', reference='DeviceReport-20261103')
        self.assertEqual(len(m.reviewed_legacy(legacy, FP)), 21)
        self.assertFalse(d['gates']['security'])

    def test_bridge_evidence_required(self):
        with self.assertRaises(m.Block):
            m.reviewed_legacy(c.template(FP), FP)

    def test_bridge_evidence_cannot_be_forged(self):
        legacy = self.bridge_legacy()
        legacy['identities'][1]['evidence_ref'] = 'some-other-reference'
        with self.assertRaises(m.Block): m.reviewed_legacy(legacy, FP)

    def test_private_creation_and_read(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.private_fixture(folder)
            path = m.create_registry(root, FP)
            self.assertEqual(path.name, m.FILENAME)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(m.read_registry(root, FP), self.basic())
            with self.assertRaises(m.Block): m.create_registry(root, FP)

    def test_refuse_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.private_fixture(folder)
            target = root / 'target.json'
            target.write_text('{}')
            (root / 'phase8-4-5-4c' / m.FILENAME).symlink_to(target)
            with self.assertRaises(m.Block): m.read_registry(root, FP)
            with self.assertRaises(m.Block): m.create_registry(root, FP)

    def test_refuse_hardlink(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.private_fixture(folder)
            path = m.create_registry(root, FP)
            os.link(path, root / 'hardlink-copy')
            with self.assertRaises(m.Block): m.read_registry(root, FP)

    def test_refuse_world_readable(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.private_fixture(folder)
            path = m.create_registry(root, FP)
            path.chmod(0o644)
            with self.assertRaises(m.Block): m.read_registry(root, FP)

    def test_save_declaration_0600(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.private_fixture(folder)
            path = m.create_registry(root, FP)
            old = m.read_registry(root, FP)
            new = m.update_declaration(old, FP, scenario='B', identity='lab',
                                       state='declared-deployed', kind='lab-log',
                                       reference='LabLog-20261103')
            self.assertTrue(m.save_declaration(root, old, new, FP))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(m.read_registry(root, FP), new)
            self.assertFalse(m.save_declaration(root, new, new, FP))

    def test_reject_changed_file_before_save(self):
        with tempfile.TemporaryDirectory() as folder:
            root = self.private_fixture(folder)
            m.create_registry(root, FP)
            old = m.read_registry(root, FP)
            new = m.update_declaration(old, FP, scenario='B', identity='lab',
                                       state='declared-deployed', kind='lab-log',
                                       reference='LabLog-20261103')
            path = m.registry_path(root)
            tampered = copy.deepcopy(old)
            tampered['scenarios']['A']['identities']['lab']['client_id_policy'] = 'fixed'
            path.write_text(json.dumps(tampered))
            with self.assertRaises(m.Block): m.save_declaration(root, old, new, FP)

    def test_summary_no_ref_printed(self):
        d = m.update_declaration(self.basic(), FP, scenario='A', identity='bridge',
                                 state='declared-deployed', kind='service-config',
                                 reference='SensitiveLocation-20261103')
        b = io.StringIO()
        with redirect_stdout(b): m.summarize(d, FP, ['fake C-v1 pending'])
        s = b.getvalue()
        self.assertNotIn('SensitiveLocation', s)
        self.assertIn('CORTE 8883 NAO AUTORIZADO', s)
        self.assertIn('1 pendencias originais', s)

    @patch.object(c, 'verify_branch')
    @patch.object(c, 'baseline', return_value=(FP, {}))
    @patch.object(c3, 'verify_bridge_source')
    @patch.object(c, 'load_model')
    def test_preflight_does_not_create(self, load, source, baseline, branch):
        load.return_value = self.bridge_legacy()
        with patch.object(m, 'create_registry') as create, \
             patch.object(m, 'save_declaration') as write, redirect_stdout(io.StringIO()):
            status = m.cli(['preflight', '--snapshot', '/fake'])
        self.assertEqual(status, 0)
        create.assert_not_called()
        write.assert_not_called()

    @patch.object(c, 'verify_branch')
    @patch.object(c, 'baseline', return_value=(FP, {}))
    @patch.object(c3, 'verify_bridge_source')
    @patch.object(c, 'load_model')
    def test_matriz_only_reads(self, load, source, baseline, branch):
        load.return_value = self.bridge_legacy()
        with patch.object(m, 'read_registry', return_value=self.basic()), \
             patch.object(m, 'create_registry') as create, \
             patch.object(m, 'save_declaration') as write, redirect_stdout(io.StringIO()):
            status = m.cli(['matriz', '--snapshot', '/fake'])
        self.assertEqual(status, 0)
        create.assert_not_called()
        write.assert_not_called()

    def test_source_never_invokes_mqtt_or_cut(self):
        source = Path(m.__file__).read_text()
        forbidden = ('subprocess.Popen', 'mosquitto_pub', 'mosquitto_ctrl',
                     'mosquitto_sub', 'socket.create_connection', 'git push',
                     'git commit', 'git checkout', 'systemctl start',
                     'shutil.copytree', 'os.system(')
        for pattern in forbidden:
            self.assertNotIn(pattern, source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
