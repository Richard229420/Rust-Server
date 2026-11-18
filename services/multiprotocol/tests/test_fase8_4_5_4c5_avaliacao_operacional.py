#!/usr/bin/env python3
"""Testes OFFLINE C.5; nao conectam a MQTT nem usam snapshot de producao."""
from __future__ import annotations

from contextlib import redirect_stdout, redirect_stderr
import copy
import hashlib
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fase8_4_5_4c5_avaliacao_operacional as m
import fase8_4_5_4c4_classificacao as c4
import fase8_4_5_4c3_evidencias as c3
import fase8_4_5_4c_prontidao_corte as c

FP = hashlib.sha256(b'fake-c5-snapshot').hexdigest()


class C5Tests(unittest.TestCase):
    def context(self):
        legacy = c3.reviewed_model(c.template(FP), FP)
        pending, _ = c.validate_model(legacy, FP)
        return m.Context(FP, tuple(pending), legacy, c4.template(FP))

    def test_c3_bridge_baseline_21(self):
        self.assertEqual(len(self.context().pending), 21)

    def test_both_scenarios(self):
        t = m.safe_report(self.context())
        self.assertIn('MATRIZ A', t)
        self.assertIn('MATRIZ B', t)

    def test_primary_operational(self):
        self.assertIn('OPERACIONAL PRINCIPAL', m.safe_report(self.context()))

    def test_secondary_lab(self):
        self.assertIn('LABORATORIO', m.safe_report(self.context()))

    def test_lab_not_falsely_confirmed(self):
        t = m.safe_report(self.context())
        self.assertIn('LAB EM A: politica CLI pendente', t)

    def test_lab_b_dynamic(self):
        t = m.safe_report(self.context())
        self.assertIn('politica=dynamic-cli', t)

    def test_lab_a_review_pending(self):
        self.assertIn('politica=security-review-pending', m.safe_report(self.context()))

    def test_bridge_static_not_runtime(self):
        self.assertIn('nao comprova execucao operacional', m.safe_report(self.context()))

    def test_sensor02_real_not_presumed(self):
        self.assertIn('nao comprova dispositivo fisico', m.safe_report(self.context()))

    def test_cut_always_blocked(self):
        self.assertIn('8883 NAO AUTORIZADO', m.safe_report(self.context()))
        self.assertIn('8883 NAO AUTORIZADO', m.plan(self.context()))

    def test_revoked_excluded(self):
        ctx = self.context()
        self.assertNotIn('device-sensor01', ctx.classification['scenarios']['A']['identities'])
        self.assertNotIn('device-sensor01', ctx.classification['scenarios']['B']['identities'])
        self.assertIn('device-sensor01 nao pode ser reabilitado', m.safe_report(ctx))

    def test_all_gates_still_false(self):
        self.assertEqual(self.context().classification['gates'],
                         {'security': False, 'git_ci': False, 'operational_readiness': False})

    def test_all_pending_grouped(self):
        self.assertEqual(m.counts(self.context().pending),
                         {'lab': 6, 'bridge': 3, 'device-sensor02': 6, 'operacionais': 6})

    def test_unknown_pending_rejected(self):
        with self.assertRaises(m.Block):
            m.counts(('arbitrary unknown obligation',))

    def test_empty_pending_valid_count(self):
        self.assertEqual(sum(m.counts(()).values()), 0)

    def test_a_declared_deployed_still_no_proof(self):
        ctx = self.context()
        model = c4.update_declaration(ctx.classification, FP, scenario='A',
                 identity='device-sensor02', state='declared-deployed',
                 kind='device-config', reference='inventory-sensor02-01')
        changed = m.Context(FP, ctx.pending, ctx.legacy, model)
        t = m.safe_report(changed)
        self.assertIn('implantacao=declared-deployed', t)
        self.assertIn('C-V1: 21 pendencias', t)
        self.assertIn('NAO HABILITADO PARA CORTE', t)

    def test_a_declared_not_deployed_not_auto_excluded(self):
        ctx = self.context()
        model = c4.update_declaration(ctx.classification, FP, scenario='A',
                  identity='device-sensor02', state='declared-not-deployed',
                  kind='deployment-inventory', reference='inventory-sensor02-02')
        t = m.safe_report(m.Context(FP, ctx.pending, ctx.legacy, model))
        self.assertIn('implantacao=declared-not-deployed', t)
        self.assertIn('C-V1: 21 pendencias', t)

    def test_b_declaration_no_a_credit(self):
        ctx = self.context()
        mod = c4.update_declaration(ctx.classification, FP, scenario='B',
                  identity='device-sensor02', state='declared-deployed',
                  kind='lab-log', reference='LabRun-20261103')
        report = m.safe_report(m.Context(FP, ctx.pending, ctx.legacy, mod))
        a, b = report.split('MATRIZ B:')
        self.assertNotIn('implantacao=declared-deployed', a)
        self.assertIn('implantacao=declared-deployed', b)
        self.assertIn('C-V1: 21 pendencias', b)

    def test_proposal_not_security_approval(self):
        ctx = self.context()
        mod = c4.propose_lab_policy(ctx.classification, FP, 'fixed-per-instance-proposed')
        report = m.safe_report(m.Context(FP, ctx.pending, ctx.legacy, mod))
        self.assertIn('politica=fixed-per-instance-proposed', report)
        self.assertIn('politica CLI pendente de aprovacao de Seguranca', report)

    def test_evidence_reference_redacted(self):
        ctx = self.context()
        mod = c4.update_declaration(ctx.classification, FP, scenario='B',
                  identity='bridge', state='declared-deployed',
                  kind='lab-log', reference='RefDoOperador-001')
        t = m.safe_report(m.Context(FP, ctx.pending, ctx.legacy, mod))
        self.assertNotIn('RefDoOperador-001', t)
        self.assertIn('evidencia=referenciada', t)

    def test_malformed_c4_rejected(self):
        ctx = self.context()
        mod = copy.deepcopy(ctx.classification)
        mod['cutover_authorized'] = True
        with self.assertRaises(c4.Block):
            m.safe_report(m.Context(FP, ctx.pending, ctx.legacy, mod))

    def test_bad_c4_external_gate_rejected(self):
        ctx = self.context()
        mod = copy.deepcopy(ctx.classification)
        mod['gates']['security'] = True
        with self.assertRaises(c4.Block):
            m.safe_report(m.Context(FP, ctx.pending, ctx.legacy, mod))

    def test_malformed_c1_rejected(self):
        ctx = self.context()
        model = copy.deepcopy(ctx.legacy)
        model['cutover_authorized'] = True
        with self.assertRaises(c.Block):
            m.safe_report(m.Context(FP, ctx.pending, model, ctx.classification))

    def test_stale_pending_rejected(self):
        ctx = self.context()
        with self.assertRaises(m.Block):
            m.safe_report(m.Context(FP, ('fake pending',), ctx.legacy, ctx.classification))

    def test_plan_contains_client_rollback(self):
        t = m.plan(self.context())
        self.assertIn('ROLLBACK POR CLIENTE', t)
        self.assertIn('bridge', t)
        self.assertIn('sensor02', t)

    def test_plan_requires_secret_channel(self):
        self.assertIn('cofre, canal autenticado', m.plan(self.context()))

    def test_plan_requires_maintenance(self):
        self.assertIn('responsaveis, janela, monitoramento', m.plan(self.context()))

    def test_plan_requires_final_snapshot(self):
        self.assertIn('snapshot FINAL', m.plan(self.context()))

    def test_plan_requires_external_gates(self):
        self.assertIn('Seguranca e Git/CI', m.plan(self.context()))

    def test_plan_does_not_trigger_changes(self):
        ctx = self.context()
        old_legacy, old_c4 = copy.deepcopy(ctx.legacy), copy.deepcopy(ctx.classification)
        m.plan(ctx)
        m.safe_report(ctx)
        self.assertEqual(ctx.legacy, old_legacy)
        self.assertEqual(ctx.classification, old_c4)

    def test_actions_read_only(self):
        self.assertEqual(m.ACTIONS, ('preflight', 'situacao', 'plano'))

    def test_no_network_or_write_imports(self):
        source = Path(m.__file__).read_text()
        for bad in ('import socket', 'import paho', 'import requests',
                    'subprocess.run(', 'os.system(', 'open(\'w\'',
                    'os.replace(', 'write_exclusive(', 'mosquitto_sub',
                    'mosquitto_pub', 'cargo run'):
            self.assertNotIn(bad, source)

    def test_main_situacao_mocked(self):
        with patch.object(m, 'verified_context', return_value=self.context()):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = m.main(['situacao', '--snapshot', '/not-real'])
        self.assertEqual(rc, 0)
        self.assertIn('C-V1: 21 pendencias', out.getvalue())

    def test_main_plano_mocked(self):
        with patch.object(m, 'verified_context', return_value=self.context()):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = m.main(['plano', '--snapshot', '/not-real'])
        self.assertEqual(rc, 0)
        self.assertIn('COLETA DE EVIDENCIAS', out.getvalue())

    def test_main_preflight_mocked(self):
        with patch.object(m, 'verified_context', return_value=self.context()):
            out = io.StringIO()
            with redirect_stdout(out):
                rc = m.main(['preflight', '--snapshot', '/not-real'])
        self.assertEqual(rc, 0)
        self.assertIn('PENDENCIAS C-V1: 21', out.getvalue())

    def test_main_blocked_mocked(self):
        with patch.object(m, 'verified_context', side_effect=c4.Block('bad')):
            err = io.StringIO()
            with redirect_stderr(err):
                rc = m.main(['situacao', '--snapshot', '/not-real'])
        self.assertEqual(rc, 2)
        self.assertIn('BLOQUEIO', err.getvalue())

    def test_context_verification_calls_gate(self):
        ctx = self.context()
        with (patch.object(c, 'verify_branch') as branch,
              patch.object(c, 'baseline', return_value=(FP, {})) as baseline,
              patch.object(c3, 'verify_bridge_source') as bridge,
              patch.object(c, 'load_model', return_value=ctx.legacy),
              patch.object(c4, 'read_registry', return_value=ctx.classification)):
            result = m.verified_context(Path('/tmp/project'), Path('/tmp/snapshot'),
                    Path('/tmp/private'), Path('/tmp/backups'), Path('/tmp/plugin'))
        self.assertEqual(result.pending, ctx.pending)
        branch.assert_called_once()
        baseline.assert_called_once()
        bridge.assert_called_once()

    def test_context_missing_c4_blocks(self):
        ctx = self.context()
        with (patch.object(c, 'verify_branch'),
              patch.object(c, 'baseline', return_value=(FP, {})),
              patch.object(c3, 'verify_bridge_source'),
              patch.object(c, 'load_model', return_value=ctx.legacy),
              patch.object(c4, 'read_registry', side_effect=c4.Block('absent'))):
            with self.assertRaises(c4.Block):
                m.verified_context(Path('/tmp/project'), Path('/tmp/snapshot'),
                    Path('/tmp/private'), Path('/tmp/backups'), Path('/tmp/plugin'))

    def test_context_rejects_unauthorized(self):
        ctx = self.context()
        invalid = copy.deepcopy(ctx.classification)
        invalid['cutover_authorized'] = True
        with (patch.object(c, 'verify_branch'),
              patch.object(c, 'baseline', return_value=(FP, {})),
              patch.object(c3, 'verify_bridge_source'),
              patch.object(c, 'load_model', return_value=ctx.legacy),
              patch.object(c4, 'read_registry', return_value=invalid)):
            with self.assertRaises(c4.Block):
                m.verified_context(Path('/tmp/project'), Path('/tmp/snapshot'),
                    Path('/tmp/private'), Path('/tmp/backups'), Path('/tmp/plugin'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
