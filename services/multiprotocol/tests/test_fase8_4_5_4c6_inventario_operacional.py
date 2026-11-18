#!/usr/bin/env python3
"""Testes offline da C.6; sem MQTT, snapshot real ou rede."""
from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
import copy
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
import fase8_4_5_4c6_inventario_operacional as m
import fase8_4_5_4c5_avaliacao_operacional as c5
import fase8_4_5_4c4_classificacao as c4
import fase8_4_5_4c3_evidencias as c3
import fase8_4_5_4c_prontidao_corte as c

FP = hashlib.sha256(b'c6-fake-snapshot').hexdigest()
DIGEST = hashlib.sha256(b'redacted-proof').hexdigest()
OTHER_DIGEST = hashlib.sha256(b'other-redacted-proof').hexdigest()


class C6Tests(unittest.TestCase):
    def sample_context(self):
        legacy = c3.reviewed_model(c.template(FP), FP)
        pending, _ = c.validate_model(legacy, FP)
        return c5.Context(FP, tuple(pending), legacy, c4.template(FP))

    def fixture(self, root: Path) -> Path:
        private = root / 'rust-server'
        private.mkdir(mode=0o700)
        (private / 'phase8-4-5-4c').mkdir(mode=0o700)
        return private

    def evidence(self, model=None, *, identity='bridge', kind='runtime-redacted',
                 reference='EvidenceBridge-20261104', digest=DIGEST):
        return m.add_reference(model if model is not None else m.template(FP), FP,
                               identity=identity, kind=kind,
                               reference=reference, digest=digest)

    def test_default_template(self):
        value = m.template(FP)
        m.validate(value, FP)
        self.assertEqual(set(value['identities']), set(c.ACCOUNTS))

    def test_scenario_a_only(self):
        self.assertEqual(m.template(FP)['scenario'], 'A')

    def test_default_cut_false(self):
        self.assertIs(m.template(FP)['cutover_authorized'], False)

    def test_all_gates_false(self):
        self.assertTrue(all(v is False for v in m.template(FP)['approvals'].values()))

    def test_no_revoked(self):
        self.assertNotIn('device-sensor01', m.template(FP)['identities'])

    def test_no_auto_evidence(self):
        self.assertTrue(all(not rows for rows in m.template(FP)['identities'].values()))

    def test_c_v1_initial_count(self):
        self.assertEqual(len(self.sample_context().pending), 21)

    def test_invalid_fingerprint_template(self):
        with self.assertRaises(m.Block): m.template('wrong')

    def test_different_fingerprint_rejected(self):
        with self.assertRaises(m.Block): m.validate(m.template(FP), 'b'*64)

    def test_revoked_injection_blocked(self):
        changed = m.template(FP)
        changed['identities']['device-sensor01'] = []
        with self.assertRaises(m.Block): m.validate(changed, FP)

    def test_other_scenario_blocked(self):
        changed = m.template(FP)
        changed['scenario'] = 'B'
        with self.assertRaises(m.Block): m.validate(changed, FP)

    def test_cut_approval_blocked(self):
        changed = m.template(FP)
        changed['cutover_authorized'] = True
        with self.assertRaises(m.Block): m.validate(changed, FP)

    def test_security_approval_blocked(self):
        changed = m.template(FP)
        changed['approvals']['security'] = True
        with self.assertRaises(m.Block): m.validate(changed, FP)

    def test_ci_approval_blocked(self):
        changed = m.template(FP)
        changed['approvals']['git_ci'] = True
        with self.assertRaises(m.Block): m.validate(changed, FP)

    def test_operational_approval_blocked(self):
        changed = m.template(FP)
        changed['approvals']['operational'] = True
        with self.assertRaises(m.Block): m.validate(changed, FP)

    def test_registration_pending_review(self):
        val = self.evidence()
        self.assertEqual(val['identities']['bridge'][0]['review_status'],
                         'pending-independent-review')

    def test_evidence_idempotent(self):
        val = self.evidence()
        self.assertEqual(val, self.evidence(val))

    def test_evidence_preserves_input(self):
        val = m.template(FP)
        self.evidence(val)
        self.assertEqual(val['identities']['bridge'], [])

    def test_unknown_identity_blocked(self):
        with self.assertRaises(m.Block): self.evidence(identity='device-sensor01')

    def test_bad_type_blocked(self):
        with self.assertRaises(m.Block): self.evidence(kind='prod-approved')

    def test_bad_digest_blocked(self):
        for digest in ('bad', 'a'*63, 'G'*64):
            with self.assertRaises(m.Block): self.evidence(digest=digest)

    def test_secret_reference_blocked(self):
        for ref in ('password-123', 'token-value-2026',
                    'credential-abc', 'sensor/path', 'https://internal'):
            with self.assertRaises(m.Block): self.evidence(reference=ref)

    def test_conflicting_ref_blocked(self):
        val = self.evidence()
        with self.assertRaises(m.Block): self.evidence(val, digest=OTHER_DIGEST)

    def test_duplicate_cross_identity_blocked(self):
        val = self.evidence()
        with self.assertRaises(m.Block): self.evidence(val, identity='lab')

    def test_second_evidence_allowed(self):
        val = self.evidence()
        val = self.evidence(val, reference='EvidenceBridge-002', digest=OTHER_DIGEST)
        self.assertEqual(len(val['identities']['bridge']), 2)

    def test_capacity_bound(self):
        val = m.template(FP)
        for i in range(m.MAX_PER_IDENTITY):
            val = self.evidence(val, reference=f'Evidence-{i:04}',
                                digest=hashlib.sha256(str(i).encode()).hexdigest())
        with self.assertRaises(m.Block):
            self.evidence(val, reference='Evidence-Overflow', digest=DIGEST)

    def test_attestation_not_approved(self):
        val = self.evidence()
        val['identities']['bridge'][0]['review_status'] = 'approved'
        with self.assertRaises(m.Block): m.validate(val, FP)

    def test_report_no_reference_or_digest(self):
        val = self.evidence()
        report = m.report_evidence(val, FP, self.sample_context().pending)
        self.assertIn('21 pendencias', report)
        self.assertNotIn('EvidenceBridge-20261104', report)
        self.assertNotIn(DIGEST, report)
        self.assertIn('8883 NAO AUTORIZADO', report)

    def test_report_b_independent(self):
        self.assertIn('CENARIO B:', m.report_evidence(m.template(FP), FP,
                                                      self.sample_context().pending))

    def test_private_index_create_and_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            m.create_index(root, FP)
            self.assertEqual(m.read_index(root, FP), m.template(FP))
            self.assertEqual(stat.S_IMODE(m.index_path(root).stat().st_mode), 0o600)

    def test_no_overwrite_existing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            m.create_index(root, FP)
            with self.assertRaises(m.Block): m.create_index(root, FP)

    def test_missing_index_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            with self.assertRaises(m.Block): m.read_index(root, FP)

    def test_public_permissions_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            m.create_index(root, FP)
            m.index_path(root).chmod(0o644)
            with self.assertRaises(m.Block): m.read_index(root, FP)

    def test_symlink_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            other = Path(tmp) / 'other.json'
            other.write_text('{}')
            m.index_path(root).symlink_to(other)
            with self.assertRaises(m.Block): m.read_index(root, FP)
            with self.assertRaises(m.Block): m.create_index(root, FP)

    def test_hardlink_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            m.create_index(root, FP)
            os.link(m.index_path(root), Path(tmp) / 'hardlink.json')
            with self.assertRaises(m.Block): m.read_index(root, FP)

    def test_saved_evidence_and_no_legacy_modification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            m.create_index(root, FP)
            before = m.read_index(root, FP)
            after = self.evidence(before)
            self.assertTrue(m.save_index(root, before, after, FP))
            self.assertEqual(m.read_index(root, FP), after)
            self.assertFalse(m.save_index(root, after, after, FP))
            self.assertEqual(stat.S_IMODE(m.index_path(root).stat().st_mode), 0o600)

    def test_conflict_on_disk_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.fixture(Path(tmp))
            m.create_index(root, FP)
            before = m.read_index(root, FP)
            after = self.evidence(before)
            m.index_path(root).write_text(json.dumps(self.evidence(before, identity='lab',
                reference='EvidenceLab-002', digest=OTHER_DIGEST)))
            with self.assertRaises(m.Block): m.save_index(root, before, after, FP)

    def test_env_names_not_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'env.sh'
            path.write_text('export RUST_SERVER_MQTT_BRIDGE_PASSWORD=TEST_SECRET_PLAINTEXT\n'
                            'RUST_SERVER_TLS_CA=/SECRET_PATH\nOTHER=HIDDEN\n')
            names = m.declared_keys(path)
            self.assertEqual(names, frozenset({'RUST_SERVER_MQTT_BRIDGE_PASSWORD',
                                                'RUST_SERVER_TLS_CA'}))
            s = m.report_inventory({'env': names, 'processes': None}, ())
            self.assertNotIn('TEST_SECRET_PLAINTEXT', s)
            self.assertNotIn('SECRET_PATH', s)
            self.assertNotIn('OTHER', s)

    def test_env_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(m.declared_keys(Path(tmp) / 'missing-env'))

    def test_env_symlink_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'a'
            p.write_text('RUST_SERVER_TLS_CA=secret\n')
            (Path(tmp) / 'b').symlink_to(p)
            with self.assertRaises(m.Block): m.declared_keys(Path(tmp) / 'b')

    def test_env_hardlink_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / 'a'
            p.write_text('RUST_SERVER_TLS_CA=secret\n')
            os.link(p, Path(tmp) / 'b')
            with self.assertRaises(m.Block): m.declared_keys(p)

    def test_proc_only_comm(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for pid, name in [('100', 'mosquitto'), ('101', 'multiprotocol'),
                              ('102', 'evil-process'), ('bad', 'mosquitto')]:
                d = root / pid
                d.mkdir()
                (d / 'comm').write_text(name + '\n')
                (d / 'environ').write_text('PASSWORD=should-never-show')
                (d / 'cmdline').write_text('--secret should-never-show')
            result = m.passive_process_counts(root)
            self.assertEqual(result['mosquitto'], 1)
            self.assertEqual(result['multiprotocol'], 1)
            self.assertNotIn('evil-process', result)
            report = m.report_inventory({'env': None, 'processes': result}, ())
            self.assertNotIn('should-never-show', report)

    def test_proc_unavailable(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(m.passive_process_counts(Path(tmp)/'missing'))

    def test_inventory_not_proof(self):
        s = m.report_inventory({'env': None, 'processes': None}, self.sample_context().pending)
        self.assertIn('NAO comprovam', s)
        self.assertIn('21', s)
        self.assertIn('8883 NAO AUTORIZADO', s)

    def test_plan_has_required_clients(self):
        text = m.plan()
        for part in ('BRIDGE', 'LAB', 'SENSOR02', 'ROLLBACK', 'Seguranca', 'Git/CI'):
            self.assertIn(part, text)

    def test_plan_no_automatic_cut(self):
        self.assertIn('NAO EXECUTAR: Mosquitto, migracao 8883', m.plan())

    def test_actions_explicit(self):
        self.assertEqual(m.ACTIONS, ('preflight','inventariar','plano','criar','registrar','avaliar'))

    def test_cli_preflight_mocked(self):
        with patch.object(m.c5, 'verified_context', return_value=self.sample_context()):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = m.main(['preflight', '--snapshot', '/not-real'])
        self.assertEqual(code, 0)
        self.assertIn('21 pendencias', buffer.getvalue())

    def test_cli_inventory_mocked(self):
        with patch.object(m.c5, 'verified_context', return_value=self.sample_context()), \
             patch.object(m, 'static_inventory', return_value={'env': None, 'processes': None}):
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = m.main(['inventariar', '--snapshot', '/not-real'])
        self.assertEqual(code, 0)
        self.assertIn('INVENTARIO PASSIVO', buffer.getvalue())

    def test_cli_create_and_evaluate_mocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = self.fixture(Path(tmp))
            with patch.object(m.c5, 'verified_context', return_value=self.sample_context()):
                with redirect_stdout(io.StringIO()):
                    created = m.main(['criar','--snapshot','/not-real','--private-root',str(private)])
                    evaluated = m.main(['avaliar','--snapshot','/not-real','--private-root',str(private)])
            self.assertEqual((created,evaluated),(0,0))

    def test_cli_register_mocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            private = self.fixture(Path(tmp))
            m.create_index(private, FP)
            with patch.object(m.c5, 'verified_context', return_value=self.sample_context()):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = m.main(['registrar','--snapshot','/not-real',
                        '--private-root',str(private),'--identidade','bridge',
                        '--tipo','runtime-redacted',
                        '--referencia','EvidenceBridge-20261104', '--sha256',DIGEST])
            self.assertEqual(code, 0)
            self.assertIn('aguarda revisao', out.getvalue())
            self.assertEqual(len(m.read_index(private, FP)['identities']['bridge']), 1)

    def test_cli_rejects_partial_register(self):
        with redirect_stderr(io.StringIO()):
            code = m.main(['registrar', '--snapshot', '/not-real',
                           '--identidade', 'bridge'])
        self.assertEqual(code, 2)

    def test_cli_prevents_extra_args(self):
        with redirect_stderr(io.StringIO()):
            code = m.main(['plano','--snapshot','/not-real', '--identidade','bridge'])
        self.assertEqual(code, 2)

    def test_cli_invalid_baseline_blocks(self):
        with patch.object(m.c5, 'verified_context', side_effect=c4.Block('bad')):
            with redirect_stderr(io.StringIO()) as err:
                code = m.main(['preflight','--snapshot','/not-real'])
        self.assertEqual(code, 2)
        self.assertIn('BLOQUEIO', err.getvalue())

    def test_no_network_client_or_repo_write(self):
        source = Path(m.__file__).read_text()
        for banned in ('import socket','import requests','import paho','mosquitto_sub(',
                       'mosquitto_pub(', 'cargo run', 'git add', 'git push',
                       'subprocess.run(', 'Popen(', 'os.system(', 'socket.connect('):
            self.assertNotIn(banned, source)


if __name__ == '__main__':
    unittest.main(verbosity=2)
