#!/usr/bin/env python3
"""Testes offline da 8.4.5.4-B; nenhuma conexao com brokers reais."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import fase8_4_5_4b_paridade_producao as mod


def legacy():
    return {**{k: set(v) for k, v in mod.audit1.LEGACY_BASE.items()},
            'device-sensor02': {'write lab/sensors/sensor02/#', 'read bus/sensors/sensor02/#'}}


def dynsec():
    mapping = mod.permissions(legacy())
    roles = [{'rolename': 'admin-role', 'acls': []}]
    clients = [{'username': mod.ADMIN, 'roles': [{'rolename': 'admin-role'}]}]
    for user in mod.ACCOUNTS:
        roles.append({'rolename': mod.role_name(user),
                      'acls': [{'acltype': a, 'topic': t, 'allow': True, 'priority': 10}
                               for a, t in mapping[user]]})
        clients.append({'username': user, 'clientid': mod.IDS[user], 'disabled': False,
                        'roles': [{'rolename': mod.role_name(user), 'priority': 10}]})
    return {'defaultACLAccess': {k: False for k in mod.DEFAULTS},
            'clients': clients, 'roles': roles, 'groups': []}


class TestPreview(unittest.TestCase):
    def test_contas_baseline(self):
        self.assertEqual(set(mod.permissions(legacy())), set(mod.ACCOUNTS))

    def test_acl_legacy_exact(self):
        p = mod.permissions(legacy())
        self.assertIn(('publishClientSend', 'lab/alerts'), p['lab'])
        self.assertIn(('subscribePattern', 'bus/alerts'), p['lab'])
        self.assertIn(('publishClientReceive', 'lab/sensors/#'), p['bridge'])
        self.assertIn(('subscribePattern', 'bus/sensors/sensor02/#'), p['device-sensor02'])

    def test_sem_acl_global(self):
        self.assertFalse(any(t == '#' for rules in mod.permissions(legacy()).values() for _, t in rules))

    def test_bloqueia_usuario_extra(self):
        d = legacy(); d['guest'] = {'read #'}
        with self.assertRaises(mod.Block): mod.permissions(d)

    def test_bloqueia_acl_ampla(self):
        d = legacy(); d['bridge'].add('read #')
        with self.assertRaises(mod.Block): mod.permissions(d)

    def test_bloqueia_acl_invertida(self):
        d = legacy(); d['lab'] = {'read lab/alerts', 'write bus/alerts'}
        with self.assertRaises(mod.Block): mod.permissions(d)

    def test_account_role_names(self):
        self.assertEqual(mod.role_name('device-sensor02'), 'phase8454b-role-sensor02')
        with self.assertRaises(mod.Block): mod.role_name('device-sensor01')

    def test_valid_state(self):
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(dynsec()).encode()):
            mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_rejeita_revogado_criado(self):
        d = dynsec(); d['clients'].append({'username': 'device-sensor01'})
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(d).encode()):
            with self.assertRaises(mod.Block): mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_rejeita_conta_extra(self):
        d = dynsec(); d['clients'].append({'username': 'lab84-bridge'})
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(d).encode()):
            with self.assertRaises(mod.Block): mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_rejeita_clientid_falso(self):
        d = dynsec(); d['clients'][1]['clientid'] = 'desconhecido'
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(d).encode()):
            with self.assertRaises(mod.Block): mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_rejeita_grupo_herdado(self):
        d = dynsec(); d['clients'][2]['groups'] = [{'groupname': 'other'}]
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(d).encode()):
            with self.assertRaises(mod.Block): mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_rejeita_role_super_admin(self):
        d = dynsec(); d['clients'][2]['roles'].append({'rolename': 'admin-role'})
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(d).encode()):
            with self.assertRaises(mod.Block): mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_rejeita_default_allow(self):
        d = dynsec(); d['defaultACLAccess']['subscribe'] = True
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(d).encode()):
            with self.assertRaises(mod.Block): mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_rejeita_acl_global_injetada(self):
        d = dynsec(); d['roles'][2]['acls'].append({'acltype': 'subscribePattern', 'topic': '#', 'allow': True})
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(d).encode()):
            with self.assertRaises(mod.Block): mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_rejeita_acl_negada_extra(self):
        d = dynsec(); d['roles'][2]['acls'][0]['allow'] = False
        with patch.object(mod.p2, 'check_regular', return_value=json.dumps(d).encode()):
            with self.assertRaises(mod.Block): mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_rejeita_json_corrompido(self):
        with patch.object(mod.p2, 'check_regular', return_value=b'{'):
            with self.assertRaises(mod.Block): mod.verify_preview(Path('/test'), mod.permissions(legacy()))

    def test_opts_0600_sem_segredo_argv(self):
        with tempfile.TemporaryDirectory() as temp:
            ca = Path(temp) / 'ca.crt'
            payload = mod.opts(ca, 'lab', 'X' * 64, mod.IDS['lab'])
            self.assertIn(b'-u lab\n', payload)
            self.assertIn(b'-i phase8454b-lab\n', payload)
            self.assertNotIn(b'8883', payload)

    def test_opts_rejeita_user_invalido(self):
        with self.assertRaises(mod.Block): mod.opts(Path('/tmp/ca'), 'device-sensor01', 'a' * 64, 'x')

    def test_init_nao_passa_senha_por_argv(self):
        with patch.object(mod, 'call') as call, patch.object(mod.os, 'chmod'), \
             patch.object(mod.p2, 'check_regular'):
            mod.init_dynsec(Path('/tmp/a'), Path('/tmp/a/production-candidate/dynamic-security.json'), 'SENHA-NEVER-LOG')
        self.assertNotIn('SENHA-NEVER-LOG', ' '.join(call.call_args.args[0]))
        self.assertIn('SENHA-NEVER-LOG', call.call_args.kwargs['input_text'])

    def test_call_suprime_output(self):
        with patch.object(mod.subprocess, 'run') as run:
            run.return_value.returncode = 1
            run.return_value.stdout = 'password-SECRET-DO-NOT-DISPLAY'
            with self.assertRaises(mod.Block) as ctx:
                mod.call(['mosquitto_ctrl', 'dynsec', 'listClients'])
            self.assertNotIn('password-SECRET', str(ctx.exception))

    def test_control_whitelist(self):
        with self.assertRaises(mod.Block): mod.control(Path('/tmp/op'), 'deleteClient', 'lab')

    def test_config_sem_portas_de_producao(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            (root/'production-candidate').mkdir()
            with patch.object(mod.p3, 'private_write') as write:
                config=mod.config(root, Path('/usr/lib/mosquitto_dynamic_security.so'))
                text=write.call_args.args[1].decode()
                self.assertIn('listener 8895 127.0.0.1', text)
                self.assertNotIn('8883', text)
                self.assertNotIn('8884', text)
                self.assertEqual(config.parent,root/'production-candidate')

    def test_wire_lengths(self):
        self.assertEqual(mod.wire_len(127), b'\x7f')
        self.assertEqual(mod.wire_len(128), b'\x80\x01')
        self.assertEqual(mod.field('x'), b'\x00\x01x')

    def test_preflight_exige_ferramenta(self):
        with patch.object(mod.p3, 'prereq'), patch.object(mod.p4, 'analyze'), \
             patch.object(mod, 'verify_plan', return_value=mod.permissions(legacy())), \
             patch.object(mod.shutil,'which',return_value=None):
            with self.assertRaises(mod.Block):
                mod.preflight(Path('/s'),Path('/b'),Path('/p'),Path('/r'),Path('/plugin'))

    def test_nao_ha_corte_via_script(self):
        import inspect
        src = inspect.getsource(mod.run)
        self.assertIn('p3.broker(cfg, PORT)', src)
        self.assertNotIn('p3.broker(cfg, 8883)', src)
        self.assertNotIn('p3.broker(cfg, 8884)', src)
        self.assertNotIn('mosquitto_passwd', src)

if __name__ == '__main__':
    unittest.main(verbosity=2)
