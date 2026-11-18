#!/usr/bin/env python3
"""Testes da consolidacao C: offline, sem broker, sem modificar cadastro real."""
from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch, Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fase8_4_5_4c_consolidar as mod
import fase8_4_5_4c_prontidao_corte as c

FP = hashlib.sha256(b'fake snapshot for offline tests').hexdigest()


class ConsolidarTests(unittest.TestCase):
    def test_status_corte_nunca_autorizado(self):
        self.assertIn('CORTE 8883 NAO AUTORIZADO', mod.LOGGED_EVIDENCE.get('XXX', '') +
                      self._captured_summary())

    @staticmethod
    def _captured_summary(pendings=None):
        out = io.StringIO()
        with redirect_stdout(out):
            mod.print_summary(pendings if pendings is not None else [],
                              {p: False for p in (8883,8884,8895,8896)}, verbose=False)
        return out.getvalue()

    def test_evidencia_relatada_nao_prova_ci(self):
        output = self._captured_summary()
        self.assertIn('logs do usuario', output)
        self.assertIn('CI remoto; nao verificados', output)

    def test_sem_copiar_identificadores_reais(self):
        output = self._captured_summary()
        self.assertNotIn('/home/arch', output)
        self.assertNotIn('password', output.lower())
        self.assertNotIn('token', output.lower())

    def test_pendencias_24_padrao(self):
        pendings, _ = c.validate_model(c.template(FP), FP)
        self.assertEqual(len(pendings), 24)
        self.assertEqual(mod.pending_counts(pendings),
                         {'lab': 6, 'bridge': 6, 'device-sensor02': 6, 'operacionais': 6})

    def test_pendencias_progridem(self):
        m = c.template(FP)
        m['identities'][1]['client_id'] = 'rust-server-bridge-local'
        pendings, _ = c.validate_model(m, FP)
        count = mod.pending_counts(pendings)
        self.assertEqual(count['bridge'], 5)
        self.assertEqual(count['lab'], 6)
        self.assertEqual(sum(count.values()), len(pendings))

    def test_completo_nao_autoriza(self):
        doc = c.template(FP)
        for n, entry in enumerate(doc['identities']):
            entry.update({'client_id': f'host-test-{n}',
                          'evidence_kind': 'runtime-observation',
                          'evidence_ref': f'ref-{n}-20261103',
                          'client_id_confirmado': True,
                          'cliente_suporta_troca_credencial': True,
                          'retorno_credencial_legada_planejado': True})
        doc['readiness'] = dict.fromkeys(c.GLOBAL_CHECKS, True)
        pendings, _ = c.validate_model(doc, FP)
        self.assertEqual(pendings, [])
        self.assertFalse(doc['cutover_authorized'])

    def test_reporta_porta_ativa_sem_encerrar(self):
        out = io.StringIO()
        with redirect_stdout(out):
            mod.print_summary([], {8883: True, 8884: False, 8895: False, 8896: False}, verbose=True)
        self.assertIn('PORTA 8883: LISTENER DETECTADO', out.getvalue())
        self.assertIn('CORTE 8883 NAO AUTORIZADO', out.getvalue())

    def test_lista_identidades_e_risco_lab(self):
        out = io.StringIO()
        with redirect_stdout(out):
            mod.print_summary([], {p: False for p in (8883,8884,8895,8896)}, verbose=True)
        self.assertIn('IDs dinamicos/por instancia para CLI lab', out.getvalue())

    def test_pin_has_only_three_reviewed_sources(self):
        self.assertEqual(set(mod.REVIEWED_SCRIPTS), {
            'scripts/fase8_4_5_4c_prontidao_corte.py',
            'scripts/fase8_4_5_4c1_bridge_rust.py',
            'scripts/fase8_4_5_4c2_clientes_mqtt.py'})
        self.assertTrue(all(len(x) == 64 for x in mod.REVIEWED_SCRIPTS.values()))

    def test_pin_matches_available_local_sources(self):
        # Os zips das subfases anteriores ficam extraidos em scripts/ no ambiente de teste.
        project = Path(__file__).resolve().parents[1]
        for relative, expected in mod.REVIEWED_SCRIPTS.items():
            path = project / relative
            self.assertTrue(path.exists(), relative)
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)

    def test_pin_bloqueia_arquivo_alterado(self):
        with tempfile.TemporaryDirectory() as d:
            project = Path(d)
            for path in mod.REVIEWED_SCRIPTS:
                dest = project / path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_text('alterado', encoding='utf-8')
            with self.assertRaises(mod.Block):
                mod.verified_sources(project)

    def test_checked_source_regular(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'mod.py'
            path.write_text('print(123)')
            self.assertEqual(mod.checked_source(path), b'print(123)')

    def test_checked_source_symlink_bloqueia(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / 'a'
            original.write_text('test')
            link = Path(d) / 'b'
            link.symlink_to(original)
            with self.assertRaises(mod.Block): mod.checked_source(link)

    def test_checked_source_hardlink_bloqueia(self):
        with tempfile.TemporaryDirectory() as d:
            original = Path(d) / 'a'
            original.write_text('test')
            linked = Path(d) / 'b'
            os.link(original, linked)
            with self.assertRaises(mod.Block): mod.checked_source(linked)

    def test_checked_source_vazio_bloqueia(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'empty'
            path.touch()
            with self.assertRaises(mod.Block): mod.checked_source(path)

    def test_checked_source_arquivo_ausente(self):
        with self.assertRaises(mod.Block): mod.checked_source(Path('/does-not-exist-fase8-4-5-4c'))

    def test_passive_ports_empty(self):
        r = Mock(returncode=0, stdout='', stderr='')
        with patch.object(mod.subprocess, 'run', return_value=r) as stub:
            ans = mod.passive_ports()
        self.assertFalse(any(ans.values()))
        self.assertEqual(stub.call_args.args[0], ['ss', '-H', '-lnt'])

    def test_passive_ports_ipv4_ipv6(self):
        output = ('LISTEN 0 128 127.0.0.1:8895 0.0.0.0:*\n'
                  'LISTEN 0 128 [::1]:8883 [::]:*\n')
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=0, stdout=output)):
            self.assertEqual(mod.passive_ports(),
                             {8883: True, 8884: False, 8895: True, 8896: False})

    def test_passive_ports_falha_bloqueia(self):
        with patch.object(mod.subprocess, 'run', return_value=Mock(returncode=1, stdout='')):
            with self.assertRaises(mod.Block): mod.passive_ports()

    def test_passive_ports_sem_ss_bloqueia(self):
        with patch.object(mod.subprocess, 'run', side_effect=OSError):
            with self.assertRaises(mod.Block): mod.passive_ports()

    @patch.object(mod, 'verified_sources')
    @patch.object(mod, 'passive_ports', return_value={8883:False, 8884:False, 8895:False, 8896:False})
    @patch.object(c, 'validate_model', return_value=(['criterio operacional pendente: x'], []))
    @patch.object(c, 'load_model', return_value={'cutover_authorized':False})
    @patch.object(c, 'baseline', return_value=(FP, {'lab':[1], 'bridge':[1], 'device-sensor02':[1]}))
    @patch.object(c, 'verify_branch')
    def test_verify_apenas_consultas(self, branch, baseline, model, validate, ports, sources):
        result, state = mod.verify(Path('/x'), Path('/s'), Path('/b'), Path('/p'), Path('/plugin'))
        self.assertEqual(len(result), 1)
        self.assertFalse(any(state.values()))
        branch.assert_called_once()
        baseline.assert_called_once()
        model.assert_called_once()
        validate.assert_called_once()
        ports.assert_called_once()
        sources.assert_called_once()

    @patch.object(mod, 'verified_sources')
    @patch.object(mod, 'passive_ports', return_value={8883:False, 8884:False, 8895:True, 8896:False})
    @patch.object(c, 'validate_model', return_value=([], []))
    @patch.object(c, 'load_model', return_value={'cutover_authorized':False})
    @patch.object(c, 'baseline', return_value=(FP, {'lab':[1], 'bridge':[1], 'device-sensor02':[1]}))
    @patch.object(c, 'verify_branch')
    def test_verify_bloqueia_listener(self, *args):
        with self.assertRaises(mod.Block):
            mod.verify(Path('/x'), Path('/s'), Path('/b'), Path('/p'), Path('/plugin'))

    @patch.object(mod, 'verified_sources')
    @patch.object(mod, 'passive_ports', return_value={8883:False, 8884:False, 8895:False, 8896:False})
    @patch.object(c, 'validate_model', return_value=([], []))
    @patch.object(c, 'load_model', return_value={'cutover_authorized':True})
    @patch.object(c, 'baseline', return_value=(FP, {'lab':[1], 'bridge':[1], 'device-sensor02':[1]}))
    @patch.object(c, 'verify_branch')
    def test_verify_nunca_autoriza(self, *args):
        with self.assertRaises(mod.Block):
            mod.verify(Path('/x'), Path('/s'), Path('/b'), Path('/p'), Path('/plugin'))

    def test_script_sem_calls_mqtt(self):
        contents = Path(mod.__file__).read_text()
        for forbidden in ('mosquitto_ctrl', 'mosquitto_pub', 'mosquitto_sub', 'cargo build',
                          'chmod(', '.write_text(', 'os.replace(', 'os.system(', 'Popen(',
                          'git add', 'git push', 'git commit'):
            self.assertNotIn(forbidden, contents)


if __name__ == '__main__':
    unittest.main(verbosity=2)
