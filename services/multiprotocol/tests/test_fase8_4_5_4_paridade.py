#!/usr/bin/env python3
"""Regressoes offline 8.4.5.4; nao tocam nos brokers ou nos dados privados."""
from __future__ import annotations

from contextlib import redirect_stdout
from copy import deepcopy
import io
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

scripts=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(scripts))
import fase8_4_5_4_paridade as mod

SECRET='NEVER_EXPOSE_PASSWORD_8-4-5-4'


def fixture():
    roles=[]
    for role, entries in mod.EXPECTED_ACLS.items():
        roles.append({'rolename':role,'acls':[{'acltype':kind,'topic':topic,'allow':True,'priority':10}
                for kind,topic in entries]})
    clients=[{'username':name,'clientid':cid,'disabled':disabled,
              'roles':[{'rolename':role,'priority':10}],
              'encoded_password':SECRET} for name,(cid,role,disabled) in mod.EXPECTED_CLIENTS.items()]
    clients.append({'username':'lab84-admin','roles':[{'rolename':'role-admin'}], 'password':SECRET})
    roles.append({'rolename':'role-admin','acls':[{'acltype':'subscribePattern','topic':'$CONTROL/#','allow':True}]})
    return {'defaultACLAccess':{k:False for k in mod.REQUIRED_DEFAULTS},
            'clients': clients,'groups':[{'groupname':'unauthenticated','roles':[]}],
            'roles':roles}


def payload(d):
    import json
    return json.dumps(d).encode()


class PolicyTests(unittest.TestCase):
    def test_baseline_lab(self):
        summary=mod.validate_dynsec(payload(fixture()))
        self.assertEqual(len(summary['clients']),4)

    def test_rejeita_default_allow(self):
        d=fixture();d['defaultACLAccess']['publishClientReceive']=True
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_default_ausente(self):
        d=fixture();del d['defaultACLAccess']['unsubscribe']
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_clientid_alheio(self):
        d=fixture();d['clients'][1]['clientid']='lab84-sensor01'
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_revogado_habilitado(self):
        d=fixture();d['clients'][0]['disabled']=False
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_sensor02_disabled(self):
        d=fixture();d['clients'][1]['disabled']=True
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_roles_elevadas(self):
        d=fixture();d['clients'][1]['roles'].append({'rolename':'role-admin'})
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_grupo_herdado(self):
        d=fixture();d['clients'][1]['groups']=[{'groupname':'unauthenticated'}]
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_acl_global(self):
        d=fixture();d['roles'][1]['acls'].append({'acltype':'publishClientSend','topic':'#','allow':True})
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_acl_duplicada(self):
        d=fixture();d['roles'][0]['acls'].append(deepcopy(d['roles'][0]['acls'][0]))
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_acl_denied_substituida(self):
        d=fixture();d['roles'][1]['acls'][0]['allow']=False
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_usuario_legado_no_lab(self):
        d=fixture();d['clients'].append({'username':'bridge'})
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_conta_extra_elevada(self):
        d=fixture(); d['clients'].append({'username':'root-admin','roles':[{'rolename':'role-admin'}]})
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_conta_repetida(self):
        d=fixture();d['clients'].append(deepcopy(d['clients'][0]))
        with self.assertRaises(mod.Block): mod.validate_dynsec(payload(d))

    def test_rejeita_json_corrompido(self):
        with self.assertRaises(mod.Block): mod.validate_dynsec(b'{')

    def test_paridade_prod_necessariamente_pendente(self):
        dyn=mod.validate_dynsec(payload(fixture()))
        legacy={'lab':set(),'bridge':set(),'device-sensor02':set()}
        gap=mod.compare_identity_sets(legacy,dyn)
        self.assertTrue(gap['sensor02_username_presente'])
        self.assertFalse(gap['identidades_iguais'])
        self.assertFalse(gap['conta_lab_presente'])
        self.assertFalse(gap['conta_bridge_presente'])
        self.assertFalse(gap['credenciais_producao_migradas'])

    def test_relatorio_nao_imprime_segredos(self):
        dyn=mod.validate_dynsec(payload(fixture()))
        gaps=mod.compare_identity_sets({'lab':set(),'bridge':set(),'device-sensor02':set()},dyn)
        out=io.StringIO()
        with redirect_stdout(out): mod.report(gaps)
        self.assertIn('PARIDADE DE PRODUCAO PENDENTE',out.getvalue())
        self.assertIn('Corte 8883 NAO AUTORIZADO',out.getvalue())
        self.assertNotIn(SECRET,out.getvalue())

    def test_teste_negativo_exige_porta_8895(self):
        with self.assertRaises(mod.Block):
            mod.mqtt5_puback_denied(Path('/missing'),'lab/sensors/sensor01/telemetry',8883,Path('/missing'))

    def test_certificado_validacao_rejeita_falha_no_openssl(self):
        with patch.object(mod.p2,'check_regular',return_value=b'FAKE'), \
             patch.object(mod.subprocess,'run') as run:
            run.return_value.returncode=1
            run.return_value.stdout=b''
            with self.assertRaisesRegex(mod.Block,'X509_STRICT'):
                mod.verify_cert(Path('/a'),Path('/b'),Path('/c'),name='teste')

    def test_broker_real_nao_e_controlado_por_paridade(self):
        from inspect import getsource
        src=getsource(mod.run_lab)
        self.assertIn('p3.broker(candidate, 8895)',src)
        self.assertIn('p3.broker(rollback, 8896)',src)
        self.assertNotIn('p3.broker(candidate, 8883)',src)
        self.assertNotIn('p3.broker(candidate, 8884)',src)

    def test_preflight_nunca_inicia_broker(self):
        with patch.object(mod.p3,'prereq') as pre,patch.object(mod,'analyze',return_value={}) as analyze:
            self.assertEqual(mod.cli_preflight(Path('/snap'),Path('/backup'),Path('/project'),Path('/private'),Path('/plugin')), {})
        pre.assert_called_once();analyze.assert_called_once()

if __name__=='__main__':
    unittest.main(verbosity=2)
