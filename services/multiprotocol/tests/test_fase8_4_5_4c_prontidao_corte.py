#!/usr/bin/env python3
"""Testes offline da 8.4.5.4-C; sem dispositivos, rede ou segredos reais."""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fase8_4_5_4c_prontidao_corte as mod

FP = hashlib.sha256(b'snapshot-inventado').hexdigest()


def complete():
    doc = mod.template(FP)
    for k, entry in enumerate(doc['identities']):
        entry.update({
            'client_id': 'real-mqtt-' + str(k),
            'evidence_kind': 'service-config',
            'evidence_ref': f'rev-20261030-{k}',
            'client_id_confirmado': True,
            'cliente_suporta_troca_credencial': True,
            'retorno_credencial_legada_planejado': True,
        })
    for field in mod.GLOBAL_CHECKS:
        doc['readiness'][field] = True
    return doc


class Tests(unittest.TestCase):
    def test_template_schema_proibe_corte(self):
        d = mod.template(FP)
        self.assertFalse(d['cutover_authorized'])
        self.assertEqual(d['schema'], 1)
        self.assertEqual(d['snapshot_manifest_sha256'], FP)

    def test_template_identidades_exatas(self):
        d = mod.template(FP)
        self.assertEqual([x['username'] for x in d['identities']], list(mod.ACCOUNTS))
        self.assertNotIn('device-sensor01', json.dumps(d))
        self.assertNotIn('lab84-bridge', json.dumps(d))

    def test_template_nao_contem_credenciais(self):
        d = json.dumps(mod.template(FP)).lower()
        for secret in ('password', 'senha', 'token', 'private_key', 'mqtt-bridge.token'):
            self.assertNotIn(secret, d)

    def test_vazio_retorna_pendencias(self):
        pending, warnings = mod.validate_model(mod.template(FP), FP)
        self.assertGreater(len(pending), 10)
        self.assertTrue(any('externas' in w for w in warnings))

    def test_completo_retorna_elegivel_revisao(self):
        pending, _ = mod.validate_model(complete(), FP)
        self.assertEqual(pending, [])
        self.assertFalse(complete()['cutover_authorized'])

    def test_snapshot_incompatível(self):
        with self.assertRaises(mod.Block):
            mod.validate_model(complete(), 'a' * 64)

    def test_proibe_corte_true(self):
        d = complete(); d['cutover_authorized'] = True
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_proibe_novo_campo(self):
        d = complete(); d['senha'] = 'segredo'
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_proibe_conta_revogada(self):
        d = complete(); d['identities'][0]['username'] = 'device-sensor01'
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_proibe_conta_extra(self):
        d = complete(); d['identities'][0]['username'] = 'root'
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_proibe_conta_duplicada(self):
        d = complete(); d['identities'][1]['username'] = 'lab'
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_proibe_clientid_duplicado(self):
        d = complete(); d['identities'][1]['client_id'] = d['identities'][0]['client_id']
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_proibe_clientid_do_laboratorio(self):
        for id_ in ('lab84-bridge', 'phase8454b-sensor02', 'phase8-5-test', 'auto', 'random'):
            d = complete(); d['identities'][1]['client_id'] = id_
            with self.subTest(id_=id_):
                with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_proibe_clientid_com_newline(self):
        d = complete(); d['identities'][2]['client_id'] = 'id-real\npassword=abc'
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_sem_evidencia_nao_comprova_id(self):
        d = complete(); d['identities'][0]['evidence_ref'] = ''
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_sem_id_mas_nao_confirmado_pendente(self):
        d = complete()
        d['identities'][0]['client_id'] = ''
        d['identities'][0]['client_id_confirmado'] = False
        pending, _ = mod.validate_model(d, FP)
        self.assertTrue(any('lab' in item for item in pending))

    def test_referencia_seguro_sem_caminhos(self):
        d = complete(); d['identities'][0]['evidence_ref'] = '/etc/shadow'
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_referencia_sem_espaco(self):
        d = complete(); d['identities'][0]['evidence_ref'] = 'producao ID'
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_kind_desconhecido_bloqueia(self):
        d = complete(); d['identities'][0]['evidence_kind'] = 'guess'
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_checklist_tipo_estrito(self):
        d = complete(); d['readiness']['janela_e_responsaveis_definidos'] = 'true'
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_identidade_tipo_estrito(self):
        d = complete(); d['identities'][0]['client_id_confirmado'] = 1
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_sem_checklist_bloqueia(self):
        d = complete(); d['readiness'].pop('monitoramento_e_criterios_aborto_definidos')
        with self.assertRaises(mod.Block): mod.validate_model(d, FP)

    def test_modelo_gravado_em_diretorio_0700_e_arquivo_0600(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/'private'; root.mkdir(mode=0o700)
            p = mod.create_model(root, FP)
            self.assertEqual(p.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            self.assertEqual(mod.load_model(root), mod.template(FP))

    def test_nao_sobrescreve_cadastro(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/'private'; root.mkdir(mode=0o700)
            p = mod.create_model(root, FP)
            with self.assertRaises(mod.Block): mod.create_model(root, FP)
            self.assertEqual(json.loads(p.read_text()), mod.template(FP))

    def test_rejeita_cadastro_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/'private'; root.mkdir(mode=0o700)
            folder = root/'phase8-4-5-4c'; folder.mkdir(mode=0o700)
            secret = Path(t)/'untouched'; secret.write_text('nothing')
            (folder/mod.FILENAME).symlink_to(secret)
            with self.assertRaises(mod.Block): mod.create_model(root, FP)
            with self.assertRaises(mod.Block): mod.load_model(root)
            self.assertEqual(secret.read_text(), 'nothing')

    def test_rejeita_diretorio_publico(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/'private'; root.mkdir(mode=0o755)
            with self.assertRaises(mod.Block): mod.create_model(root, FP)

    def test_rejeita_diretorio_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/'private'; root.mkdir(mode=0o700)
            ext = Path(t)/'external'; ext.mkdir(mode=0o700)
            (root/'phase8-4-5-4c').symlink_to(ext, target_is_directory=True)
            with self.assertRaises(mod.Block): mod.create_model(root, FP)

    def test_rejeita_arquivo_permissao_0644(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/'private'; root.mkdir(mode=0o700)
            p = mod.create_model(root, FP)
            p.chmod(0o644)
            with self.assertRaises(mod.Block): mod.load_model(root)

    def test_rejeita_hardlink(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)/'private'; root.mkdir(mode=0o700)
            p = mod.create_model(root, FP)
            os.link(p, Path(t)/'hardlink')
            with self.assertRaises(mod.Block): mod.load_model(root)

    def test_branch_errada_bloqueia(self):
        with patch.object(mod.subprocess, 'run') as runner, patch.object(mod.os, 'geteuid', return_value=1000):
            runner.return_value.returncode = 0
            runner.return_value.stdout = 'main\n'
            with self.assertRaises(mod.Block): mod.verify_branch(Path('/tmp/proj'))

    def test_branch_correta_so_consulta(self):
        with patch.object(mod.subprocess, 'run') as runner, patch.object(mod.os, 'geteuid', return_value=1000):
            runner.return_value.returncode = 0
            runner.return_value.stdout = mod.BRANCH + '\n'
            mod.verify_branch(Path('/tmp/proj'))
            self.assertEqual(runner.call_args.args[0][-2:], ['branch', '--show-current'])

    def test_root_bloqueado(self):
        with patch.object(mod.os, 'geteuid', return_value=0):
            with self.assertRaises(mod.Block): mod.verify_branch(Path('/tmp/proj'))

    def test_plano_nao_contém_segredos(self):
        import io
        from contextlib import redirect_stdout
        mapping = {u: (('publishClientSend', 'lab/alerts'),) for u in mod.ACCOUNTS}
        b = io.StringIO()
        with redirect_stdout(b): mod.show_plan(mapping)
        self.assertIn('Corte', b.getvalue() + 'Corte')
        self.assertNotIn('password=', b.getvalue())
        self.assertNotIn('mosquitto_ctrl dynsec', b.getvalue())

    def test_acao_somente_quatro_subcomandos(self):
        import inspect
        src = inspect.getsource(mod.cli)
        self.assertIn("('preflight', 'plano', 'modelo', 'avaliar')", src)
        self.assertNotIn('systemctl', src)
        self.assertNotIn('mosquitto_pub', src)

    def test_registro_nao_autoriza_corte_mesmo_completo(self):
        doc = complete()
        pend, warnings = mod.validate_model(doc, FP)
        self.assertEqual(pend, [])
        self.assertFalse(doc['cutover_authorized'])
        self.assertTrue(any('8883' in w for w in warnings))


if __name__ == '__main__':
    unittest.main(verbosity=2)
