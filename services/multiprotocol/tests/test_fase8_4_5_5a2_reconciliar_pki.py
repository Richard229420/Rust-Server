#!/usr/bin/env python3
"""Testes A.2: todos isolados em temporarios; nunca tocam no broker do operador."""
from __future__ import annotations
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).absolute().parent.parent / 'scripts'))
# Este import so serve aos testes no ambiente de montagem; no Arch a pasta scripts/ ja contem p2.
from fase8_4_5_5a2_reconciliar_pki import (Block, EXPECTED_CHANGED, NAME, PHASE,
    create, delta, historic_bytes, inspect, make_manifest, messages, sha, source_bytes,
    tls_checks, validate_manifest, verify_candidate, verify_historical_and_registries)
import fase8_4_5_5a2_reconciliar_pki as m
import fase8_4_5_2_preparar as p2


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='rust-server-a2-tls-')
        d = Path(cls.tmp.name)
        ca = d/'ca.crt'
        ca_key = d/'ca.key'
        srv = d/'server.crt'
        srv_key = d/'server.key'
        csr = d/'server.csr'
        ext = d/'ext.cnf'
        ext.write_text('basicConstraints=critical,CA:FALSE\n'
                       'keyUsage=critical,digitalSignature,keyEncipherment\n'
                       'extendedKeyUsage=serverAuth\n'
                       'subjectAltName=DNS:localhost,IP:127.0.0.1\n')
        def openssl(*args):
            subprocess.run(['openssl', *map(str,args)], stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, check=True, timeout=30)
        openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2',
                '-subj','/CN=A2-LOCAL-CA','-keyout',ca_key,'-out',ca,
                '-addext','basicConstraints=critical,CA:TRUE',
                '-addext','keyUsage=critical,keyCertSign,cRLSign')
        openssl('req','-newkey','rsa:2048','-nodes','-keyout',srv_key,'-out',csr,
                '-subj','/CN=localhost')
        openssl('x509','-req','-in',csr,'-CA',ca,'-CAkey',ca_key,
                '-CAcreateserial','-days','2','-out',srv,'-extfile',ext)
        cls.ca, cls.cert, cls.key = ca.read_bytes(), srv.read_bytes(), srv_key.read_bytes()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def setUp(self):
        self.old = {label: ('old='+label).encode() for label in p2.SPECS}
        self.now = self.old.copy()
        self.now.update({'lab/pki/ca.crt': self.ca,
                         'lab/pki/server.crt': self.cert,
                         'lab/pki/server.key': self.key})
        self.fp = sha(b'old-original-manifest')

    def test_exact_names(self):
        self.assertEqual(len(EXPECTED_CHANGED), 3)
        self.assertEqual(len(p2.SPECS), 20)
        self.assertEqual(len(delta(self.old,self.now)), 3)
        self.assertEqual(set(delta(self.old,self.now)), EXPECTED_CHANGED)

    def test_delta_no_change(self):
        self.assertEqual(delta(self.old,self.old), ())

    def test_delta_added_other(self):
        new = self.now.copy(); new['legacy/acl'] += b'X'
        self.assertIn('legacy/acl', delta(self.old,new))

    def test_delta_missing(self):
        new = self.now.copy(); new.pop('legacy/acl')
        with self.assertRaises(Block): delta(self.old,new)

    def test_valid_tls(self):
        tls_checks(self.ca, self.cert, self.key)

    def test_tls_wrong_key(self):
        with self.assertRaises(Block): tls_checks(self.ca, self.cert, b'not-a-key')

    def test_tls_wrong_ca(self):
        with self.assertRaises(Block): tls_checks(self.cert, self.cert, self.key)

    def test_tls_bad_cert(self):
        with self.assertRaises(Block): tls_checks(self.ca, b'invalid-cert', self.key)

    def test_tls_empty(self):
        with self.assertRaises(Block): tls_checks(self.ca, self.cert, b'')

    def test_manifest_template(self):
        man = make_manifest(self.fp, self.old, self.now)
        validate_manifest(man, self.fp)
        self.assertEqual(len(man['files']),20)
        self.assertEqual(man['phase'],PHASE)
        self.assertEqual(man['c_v1_pending'],21)
        self.assertIs(man['cutover_authorized'],False)

    def test_manifest_wrong_fingerprint(self):
        with self.assertRaises(Block): make_manifest('x',self.old,self.now)

    def test_manifest_non_pki_change(self):
        bad = self.now.copy(); bad['legacy/acl'] += b'bad'
        with self.assertRaises(Block): make_manifest(self.fp,self.old,bad)

    def test_manifest_missing_file(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['files'].pop()
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_cut_false_type_zero(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['cutover_authorized'] = 0
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_approval_true(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['external_approvals']['security'] = True
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_approval_zero(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['external_approvals']['git_ci'] = 0
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_decision_go(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['decision'] = 'GO'
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_pending_changed(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['c_v1_pending'] = 20
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_provenance_forged(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['pki_provenance'] = 'approved'
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_migrated_legacy_forged(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['legacy_registries_migrated'] = True
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_snapshot_forged(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['historical_snapshot_replaced'] = True
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_final_backup_forged(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['final_maintenance_backup'] = True
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_sensor01_not_registered(self):
        man = make_manifest(self.fp,self.old,self.now)
        self.assertIs(man['revoked_identity_unchanged'], True)
        self.assertIn('lab/clients/device-sensor01.opts', [r['name'] for r in man['files']])
        self.assertNotIn('device-sensor01', man.keys())

    def test_manifest_extra_key(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['migration_port'] = 8883
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_status_wrong(self):
        man = make_manifest(self.fp,self.old,self.now)
        man['files'][0]['status']='changed-pki'
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def test_manifest_same_hash_for_changed(self):
        man = make_manifest(self.fp,self.old,self.now)
        changed = next(r for r in man['files'] if r['name']=='lab/pki/ca.crt')
        changed['candidate_sha256']=changed['historic_sha256']
        with self.assertRaises(Block): validate_manifest(man,self.fp)

    def _make_candidate(self, base: Path) -> Path:
        base.mkdir(mode=0o700, exist_ok=True)
        cand=base/'candidato-test'
        cand.mkdir(mode=0o700)
        for label, raw in self.now.items():
            where=cand/'files'/label
            p2.mkdirs_locked(cand, __import__('pathlib').PurePosixPath('files') / __import__('pathlib').PurePosixPath(label).parent)
            p2.write_exclusive(where,raw)
        p2.write_exclusive(cand/NAME, (json.dumps(make_manifest(self.fp,self.old,self.now))+'\n').encode())
        return cand

    def test_candidate_integrity(self):
        with tempfile.TemporaryDirectory() as tmp:
            cand=self._make_candidate(Path(tmp))
            verify_candidate(cand,self.fp,self.old,check_name=False)

    def test_candidate_tamper_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cand=self._make_candidate(Path(tmp))
            (cand/'files/lab/pki/server.crt').write_bytes(b'different')
            with self.assertRaises((Block,p2.Block)):
                verify_candidate(cand,self.fp,self.old,check_name=False)

    def test_candidate_tamper_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            cand=self._make_candidate(Path(tmp))
            man=json.loads((cand/NAME).read_text()); man['decision']='GO'
            (cand/NAME).write_text(json.dumps(man))
            with self.assertRaises((Block,p2.Block)):
                verify_candidate(cand,self.fp,self.old,check_name=False)

    def test_candidate_symlink_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cand=self._make_candidate(Path(tmp))
            path=cand/'files/lab/pki/server.crt'; path.unlink()
            path.symlink_to(cand/'files/lab/pki/ca.crt')
            with self.assertRaises((Block,p2.Block)):
                verify_candidate(cand,self.fp,self.old,check_name=False)

    def test_candidate_hardlink_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cand=self._make_candidate(Path(tmp))
            path=cand/'files/lab/pki/server.crt'; path.unlink()
            os.link(cand/'files/lab/pki/ca.crt', path)
            with self.assertRaises((Block,p2.Block)):
                verify_candidate(cand,self.fp,self.old,check_name=False)

    def test_candidate_public_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            cand=self._make_candidate(Path(tmp))
            (cand/NAME).chmod(0o644)
            with self.assertRaises((Block,p2.Block)):
                verify_candidate(cand,self.fp,self.old,check_name=False)

    def test_candidate_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            cand=self._make_candidate(Path(tmp))
            (cand/'files/legacy/acl').unlink()
            with self.assertRaises((Block,p2.Block)):
                verify_candidate(cand,self.fp,self.old,check_name=False)

    def test_candidate_wrong_location(self):
        with tempfile.TemporaryDirectory() as tmp:
            cand=self._make_candidate(Path(tmp))
            with self.assertRaises(Block):
                verify_candidate(cand,self.fp,self.old,check_name=True)

    def test_full_candidate_create_local_temp(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'secure-root'
            root.mkdir(mode=0o700)
            with patch.object(m,'inspect',return_value=(self.fp,self.old,self.now)), \
                 patch.object(m,'target_root_ok',return_value=None), \
                 patch.object(m,'source_bytes',return_value=self.now), \
                 patch.object(m,'verify_candidate',side_effect=lambda path,fp,old,**kw:
                              verify_candidate(path,fp,old,check_name=False)):
                result=create(Path(tmp),Path(tmp),Path(tmp),Path(tmp),root,Path(tmp))
            self.assertTrue(result.is_dir())
            self.assertEqual((result/NAME).stat().st_mode&0o777,0o600)
            self.assertEqual(result.stat().st_mode&0o777,0o700)
            self.assertEqual(sum(p.is_file() for p in (result/'files').rglob('*')),20)

    def test_full_candidate_no_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'secure-root'
            root.mkdir(mode=0o700)
            with patch.object(m,'inspect',return_value=(self.fp,self.old,self.now)), \
                 patch.object(m,'target_root_ok',return_value=None), \
                 patch.object(m,'source_bytes',return_value=self.now), \
                 patch.object(m,'secrets') as random, \
                 patch.object(m,'verify_candidate',side_effect=lambda path,fp,old,**kw:
                              verify_candidate(path,fp,old,check_name=False)):
                random.token_hex.return_value='fixed'
                create(Path(tmp),Path(tmp),Path(tmp),Path(tmp),root,Path(tmp))
                with self.assertRaises(Block):
                    create(Path(tmp),Path(tmp),Path(tmp),Path(tmp),root,Path(tmp))

    def test_inspect_ok_in_isolation(self):
        with patch.object(m,'verify_historical_and_registries',return_value=self.fp), \
             patch.object(m,'historic_bytes',return_value=self.old), \
             patch.object(m,'source_bytes',return_value=self.now), \
             patch.object(m,'tls_checks') as tls:
            fp, _, _=inspect(Path('/x'),Path('/x'),Path('/x'),Path('/x'),Path('/x'))
            self.assertEqual(fp,self.fp); tls.assert_called_once()

    def test_inspect_reject_unrelated_change(self):
        bad=self.now.copy();bad['legacy/acl']+=b'bad'
        with patch.object(m,'verify_historical_and_registries',return_value=self.fp), \
             patch.object(m,'historic_bytes',return_value=self.old), \
             patch.object(m,'source_bytes',return_value=bad), \
             patch.object(m,'tls_checks') as tls:
            with self.assertRaises(Block):
                inspect(Path('/x'),Path('/x'),Path('/x'),Path('/x'),Path('/x'))
            tls.assert_not_called()

    def test_inspect_reject_source_drift(self):
        drift=self.now.copy();drift['legacy/acl']+=b'bad'
        with patch.object(m,'verify_historical_and_registries',return_value=self.fp), \
             patch.object(m,'historic_bytes',return_value=self.old), \
             patch.object(m,'source_bytes',side_effect=[self.now,drift]), \
             patch.object(m,'tls_checks'):
            with self.assertRaises(Block):
                inspect(Path('/x'),Path('/x'),Path('/x'),Path('/x'),Path('/x'))

    def test_root_rejected(self):
        with patch.object(m.os,'geteuid',return_value=0):
            with self.assertRaises(Block):
                verify_historical_and_registries(Path('/x'),Path('/x'),Path('/x'),
                                                 Path('/x'),Path('/x'))

    def test_historical_registry_without_origin_bypass(self):
        root=Path('/x/backup')
        snap=root/'snapshot-test'
        with patch.object(m.os,'geteuid',return_value=1000), \
             patch.object(m.p2,'backup_root_ok'), patch.object(m.p2,'verify'), \
             patch.object(m.c,'verify_branch'), \
             patch.object(m.c,'manifest_fingerprint',return_value=self.fp), \
             patch.object(m.c,'load_model',return_value={}), \
             patch.object(m.c4,'reviewed_legacy',return_value=['p']*21), \
             patch.object(m.c4,'read_registry'), patch.object(m.c6,'read_index'), \
             patch.object(m.c7,'read_collection'):
            self.assertEqual(verify_historical_and_registries(Path('/x'),Path('/x'),
                                         snap,root,Path(__file__)), self.fp)

    def test_historical_registry_20_pending_rejected(self):
        root=Path('/x/backup'); snap=root/'snapshot-test'
        with patch.object(m.os,'geteuid',return_value=1000), \
             patch.object(m.p2,'backup_root_ok'), patch.object(m.p2,'verify'), \
             patch.object(m.c,'verify_branch'), \
             patch.object(m.c,'manifest_fingerprint',return_value=self.fp), \
             patch.object(m.c,'load_model',return_value={}), \
             patch.object(m.c4,'reviewed_legacy',return_value=['p']*20):
            with self.assertRaises(Block):
                verify_historical_and_registries(Path('/x'),Path('/x'),snap,root,Path('/x'))

    def test_cli_missing_snapshot(self):
        self.assertEqual(m.main(['preflight']),2)

    def test_safe_plan(self):
        self.assertIn('NO-GO',messages())
        self.assertIn('21 pendencias',messages())
        self.assertIn('Cenario A principal',messages())

    def test_script_does_not_restart(self):
        source=Path(m.__file__).read_text()
        for symbol in ('mosquitto_ctrl','subprocess.Popen(','os.system(','shutil.rmtree('):
            self.assertNotIn(symbol,source)


if __name__=='__main__':
    unittest.main(verbosity=2)
