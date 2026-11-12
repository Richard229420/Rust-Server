#!/usr/bin/env python3
"""Testes offline C.7; nenhum MQTT, root real, credencial ou rede."""
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
import fase8_4_5_4c7_coleta_evidencias as m
import fase8_4_5_4c6_inventario_operacional as c6
import fase8_4_5_4c5_avaliacao_operacional as c5
import fase8_4_5_4c4_classificacao as c4
import fase8_4_5_4c3_evidencias as c3
import fase8_4_5_4c_prontidao_corte as c

FP = hashlib.sha256(b'c7-snapshot-fixture').hexdigest()
STAMP = '2026-11-04T16:00:00+00:00'


class C7Tests(unittest.TestCase):
    def context(self):
        legacy = c3.reviewed_model(c.template(FP), FP)
        pending, _ = c.validate_model(legacy, FP)
        return c5.Context(FP, tuple(pending), legacy, c4.template(FP))

    def fixture(self, root: Path):
        private = root / 'priv'
        private.mkdir(mode=0o700)
        (private / 'phase8-4-5-4c').mkdir(mode=0o700)
        project = root / 'project'
        (project / 'scripts').mkdir(parents=True)
        (project / 'scripts/test_phase8_1_mqtt_auth.sh').write_text('# lab\n')
        (project / 'scripts/diagnosticar_mqtt_fase8.sh').write_text('# diagnóstico\n')
        (project / 'scripts/test_phase8_3_devices.sh').write_text('# sensor\n')
        (project / 'scripts/env_phase8.sh').write_text(
            'export RUST_SERVER_MQTT_BRIDGE_PASSWORD="FAKE_DO_NOT_PRINT"\n'
            'export RUST_SERVER_MQTT_LAB_PASSWORD="FAKE_DO_NOT_PRINT"\n'
            'export RUST_SERVER_TLS_CA="FAKE_DO_NOT_PRINT"\n', encoding='utf8')
        proc = root / 'proc'
        proc.mkdir()
        for pid, command in [(101,'multiprotocol'), (102,'mosquitto_pub'),
                             (103,'mosquitto_sub'), (104,'not-MQTT')]:
            p = proc / str(pid)
            p.mkdir()
            (p / 'comm').write_text(command + '\n')
        return private, project, proc

    def collect(self, root: Path, *, index=None, context=None):
        private, project, proc = self.fixture(root)
        model = m.collect(project, context or self.context(), index or c6.template(FP),
                          proc_root=proc, observed_at=STAMP)
        return private, project, proc, model

    def test_pending_21_baseline(self):
        self.assertEqual(len(self.context().pending), 21)

    def test_const_scenarios(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertEqual((obj['scenario_primary'],obj['scenario_secondary']), ('A','B'))

    def test_identities_exact(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertEqual(set(obj['clients']), {'lab','bridge','device-sensor02'})

    def test_revoked_excluded(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertNotIn('device-sensor01', json.dumps(obj))

    def test_no_automatic_cut(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertIs(obj['cutover_authorized'], False)

    def test_all_external_gates_false(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertEqual(obj['external_approvals'], m.APPROVALS)

    def test_bridge_static_only(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertEqual(obj['clients']['bridge']['source_client_id'], 'rust-server-bridge-local')
            self.assertIs(obj['clients']['bridge']['operational_runtime_proven'], False)

    def test_process_count_not_evidence(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertEqual(obj['clients']['bridge']['possible_processes'], 1)
            self.assertIs(obj['clients']['bridge']['operational_runtime_proven'], False)

    def test_lab_processes_not_operators(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            lab = obj['clients']['lab']
            self.assertEqual((lab['possible_pub_processes'], lab['possible_sub_processes']), (1, 1))
            self.assertIs(lab['operators_or_deployment_proven'], False)

    def test_lab_policy_remains_pending(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertIs(obj['clients']['lab']['scenario_a_policy_approved'], False)

    def test_sensor_is_not_inferred(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertIs(obj['clients']['device-sensor02']['actual_deployment_proven'], False)
            self.assertIs(obj['clients']['device-sensor02']['remote_device_examined'], False)

    def test_env_declared_not_values(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertTrue(obj['clients']['bridge']['bridge_password_env_name_declared'])
            self.assertTrue(obj['clients']['lab']['lab_password_env_name_declared'])
            self.assertIs(obj['clients']['bridge']['mqtt_addr_env_name_declared'], False)
            self.assertNotIn('FAKE_DO_NOT_PRINT', json.dumps(obj))

    def test_env_absent_not_false(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            (project/'scripts/env_phase8.sh').unlink()
            obj = m.collect(project, self.context(), c6.template(FP), proc_root=proc, observed_at=STAMP)
            self.assertIsNone(obj['clients']['lab']['lab_password_env_name_declared'])

    def test_process_root_absent_not_zero(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            obj = m.collect(project, self.context(), c6.template(FP), proc_root=proc/'absent', observed_at=STAMP)
            self.assertIsNone(obj['clients']['bridge']['possible_processes'])

    def test_script_presence_only(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            self.assertTrue(obj['clients']['device-sensor02']['device_test_script_file_present'])
            self.assertTrue(all(obj['clients']['lab']['cli_script_files_present'].values()))

    def test_script_missing_is_not_proof(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            (project/'scripts/test_phase8_3_devices.sh').unlink()
            obj = m.collect(project, self.context(), c6.template(FP), proc_root=proc, observed_at=STAMP)
            self.assertIs(obj['clients']['device-sensor02']['device_test_script_file_present'], False)
            self.assertIs(obj['clients']['device-sensor02']['actual_deployment_proven'], False)

    def test_script_symlink_block(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            orig = project/'scripts/test_phase8_3_devices.sh'
            orig.unlink()
            orig.symlink_to(project/'scripts/test_phase8_1_mqtt_auth.sh')
            with self.assertRaises(m.Block):
                m.collect(project, self.context(), c6.template(FP), proc_root=proc, observed_at=STAMP)

    def test_script_hardlink_block(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            os.link(project/'scripts/test_phase8_3_devices.sh', project/'scripts/hardcopy')
            with self.assertRaises(m.Block):
                m.collect(project, self.context(), c6.template(FP), proc_root=proc, observed_at=STAMP)

    def test_invalid_fingerprint(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            with self.assertRaises(m.Block): m.validate(obj, 'b'*64)

    def test_stale_pending_refused(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            ctx = self.context()
            ctx = c5.Context(ctx.fingerprint, ctx.pending[:-1], ctx.legacy, ctx.classification)
            with self.assertRaises(m.Block):
                m.collect(project, ctx, c6.template(FP), proc_root=proc, observed_at=STAMP)

    def test_c6_bad_index_refused(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            idx = c6.template(FP)
            idx['approvals']['security'] = True
            with self.assertRaises(c6.Block):
                m.collect(project, self.context(), idx, proc_root=proc, observed_at=STAMP)

    def test_c6_index_counts(self):
        with tempfile.TemporaryDirectory() as d:
            idx = c6.add_reference(c6.template(FP), FP, identity='bridge',
                                  kind='configuration-redacted', reference='Bridge-C7-Source-001',
                                  digest=hashlib.sha256(b'redacted').hexdigest())
            *_, obj = self.collect(Path(d), index=idx)
            self.assertEqual(obj['c6_indexed_reference_counts']['bridge'], 1)
            self.assertNotIn('Bridge-C7-Source-001', json.dumps(obj))

    def test_default_no_index_change(self):
        with tempfile.TemporaryDirectory() as d:
            idx = c6.template(FP)
            before = copy.deepcopy(idx)
            *_, obj = self.collect(Path(d), index=idx)
            self.assertEqual(idx, before)

    def test_no_personal_paths_in_output(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            report = m.safe_summary(obj, FP)
            self.assertNotIn(str(Path(d)), report)
            self.assertNotIn('FAKE_DO_NOT_PRINT', report)

    def test_good_timestamp(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            m.validate(obj, FP)

    def test_bad_timestamp(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['collected_at_utc'] = 'yesterday'
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_schema_extra_key(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['password'] = 'fake'
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_false_claim_bridge(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['clients']['bridge']['operational_runtime_proven'] = True
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_false_claim_lab(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['clients']['lab']['operators_or_deployment_proven'] = True
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_false_claim_sensor(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['clients']['device-sensor02']['actual_deployment_proven'] = True
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_revoked_injection(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['clients']['device-sensor01'] = {}
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_fake_security_approval(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['external_approvals']['security'] = True
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_approval_zero_is_not_boolean_false(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['external_approvals']['security'] = 0
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_fake_ci_approval(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['external_approvals']['git_ci'] = True
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_fake_operational_approval(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['external_approvals']['operational'] = True
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_cutover_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['cutover_authorized'] = True
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_altered_limits_refused(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['limitations']['no_broker_contact'] = False
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_modified_pending_refused(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['c_v1_pending'] = 20
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_invalid_process_count_bool(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['clients']['bridge']['possible_processes'] = True
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_invalid_process_count_negative(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['clients']['bridge']['possible_processes'] = -1
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_invalid_deployment_status(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['classification_declarations']['A']['bridge'] = 'approved'
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_differing_c6_count_excess(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['c6_indexed_reference_counts']['bridge'] = 999
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_extra_script_key_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            obj['clients']['lab']['cli_script_files_present']['/etc/passwd'] = True
            with self.assertRaises(m.Block): m.validate(obj, FP)

    def test_write_private_read(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            path = m.write_once(private, obj, FP)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(m.read_collection(private, FP), obj)

    def test_write_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            m.write_once(private, obj, FP)
            with self.assertRaises(m.Block): m.write_once(private, obj, FP)

    def test_write_no_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            target = m.collection_path(private)
            target.symlink_to(project/'scripts/env_phase8.sh')
            with self.assertRaises(m.Block): m.write_once(private, obj, FP)

    def test_read_no_symlink(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            target = m.collection_path(private)
            target.symlink_to(project/'scripts/env_phase8.sh')
            with self.assertRaises(m.Block): m.read_collection(private, FP)

    def test_read_no_public(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            path = m.write_once(private, obj, FP)
            path.chmod(0o644)
            with self.assertRaises(m.Block): m.read_collection(private, FP)

    def test_read_no_hardlink(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            path = m.write_once(private, obj, FP)
            os.link(path, path.with_name('c7-other.json'))
            with self.assertRaises(m.Block): m.read_collection(private, FP)

    def test_read_no_corruption(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            path = m.write_once(private, obj, FP)
            path.write_text('{bad')
            with self.assertRaises(m.Block): m.read_collection(private, FP)

    def test_file_nocopy_secrets(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            path = m.write_once(private, obj, FP)
            self.assertNotIn('FAKE_DO_NOT_PRINT', path.read_text())

    def test_no_other_cadastros_created(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            m.write_once(private, obj, FP)
            dirname = private/'phase8-4-5-4c'
            self.assertEqual({x.name for x in dirname.iterdir()}, {m.FILENAME})

    def test_summary_never_production_approved(self):
        with tempfile.TemporaryDirectory() as d:
            *_, obj = self.collect(Path(d))
            result = m.safe_summary(obj, FP)
            self.assertIn('CORTE 8883 NAO AUTORIZADO', result)
            self.assertIn('21 pendencias', result)
            self.assertNotIn('real validado', result)

    def test_roteiro_gates(self):
        output = m.plan()
        self.assertIn('Seguranca e Git/CI', output)
        self.assertIn('21 pendencias', output)
        self.assertIn('NAO EXECUTAR', output)

    def test_no_external_service_calls(self):
        src = Path(m.__file__).read_text()
        for word in ('subprocess.run(', 'subprocess.Popen(', 'socket.socket(', 'os.system(',
                     'mosquitto_pub -', 'mosquitto_sub -', 'git push', 'exec('):
            self.assertNotIn(word, src)

    def test_preflight_mock(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            ctx = self.context()
            idx = c6.template(FP)
            with (patch.object(m, 'verified_context', return_value=(ctx,idx)),
                  patch.object(m.os, 'geteuid', side_effect=[1000] + [os.geteuid()] * 100)):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = m.main(['preflight','--snapshot',str(Path(d)/'snap'),
                                   '--project-root',str(project),'--private-root',str(private)])
                self.assertEqual(code,0)
                self.assertIn('21 pendencias',out.getvalue())

    def test_collect_main_mock(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            ctx = self.context()
            idx = c6.template(FP)
            with (patch.object(m, 'verified_context', return_value=(ctx,idx)),
                  patch.object(m.c6, 'static_inventory', return_value={'env':frozenset(),
                      'processes':{'multiprotocol':0,'mosquitto_pub':0,'mosquitto_sub':0,'mosquitto':0}}),
                  patch.object(m.os, 'geteuid', side_effect=[1000] + [os.geteuid()] * 100)):
                out = io.StringIO()
                args = ['coletar','--snapshot',str(Path(d)/'snap'),
                        '--project-root',str(project),'--private-root',str(private)]
                with redirect_stdout(out):
                    code = m.main(args)
                self.assertEqual(code,0)
                self.assertIn('coleta PASSIVA',out.getvalue())
                self.assertTrue(m.collection_path(private).is_file())
                self.assertFalse(any('revogado' in x for x in os.listdir(private/'phase8-4-5-4c')))

    def test_verificar_main_mock(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            m.write_once(private, obj, FP)
            with (patch.object(m, 'verified_context', return_value=(self.context(),c6.template(FP))),
                  patch.object(m.os, 'geteuid', side_effect=[1000] + [os.geteuid()] * 100)):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = m.main(['verificar','--snapshot',str(Path(d)/'snap'),
                                  '--project-root',str(project),'--private-root',str(private)])
                self.assertEqual(code,0)
                self.assertIn('21 pendencias',out.getvalue())

    def test_roteiro_main_mock(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            with (patch.object(m, 'verified_context', return_value=(self.context(),c6.template(FP))),
                  patch.object(m.os, 'geteuid', side_effect=[1000] + [os.geteuid()] * 100)):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = m.main(['roteiro','--snapshot',str(Path(d)/'snap'),
                                   '--project-root',str(project),'--private-root',str(private)])
                self.assertEqual(code,0)
                self.assertIn('C.7',out.getvalue())

    def test_resumo_main_mock(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc, obj = self.collect(Path(d))
            m.write_once(private, obj, FP)
            with (patch.object(m, 'verified_context', return_value=(self.context(),c6.template(FP))),
                  patch.object(m.os, 'geteuid', side_effect=[1000] + [os.geteuid()] * 100)):
                out = io.StringIO()
                with redirect_stdout(out):
                    code = m.main(['resumo','--snapshot',str(Path(d)/'snap'),
                                   '--project-root',str(project),'--private-root',str(private)])
                self.assertEqual(code,0)
                self.assertIn('C.7',out.getvalue())

    def test_root_rejected(self):
        out = io.StringIO()
        with patch.object(m.os,'geteuid',return_value=0), redirect_stderr(out):
            self.assertEqual(m.main(['preflight','--snapshot','/fake/path']),2)
        self.assertIn('BLOQUEIO',out.getvalue())

    def test_missing_index_blocks_main(self):
        with tempfile.TemporaryDirectory() as d:
            private, project, proc = self.fixture(Path(d))
            with (patch.object(m.c5, 'verified_context', return_value=self.context()),
                  patch.object(m.os, 'geteuid', side_effect=[1000] + [os.geteuid()] * 100)):
                out = io.StringIO()
                with redirect_stderr(out):
                    code = m.main(['preflight','--snapshot',str(Path(d)/'snap'),
                                   '--project-root',str(project),'--private-root',str(private)])
                self.assertEqual(code,2)
                self.assertIn('CORTE 8883 NAO AUTORIZADO',out.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
