#!/usr/bin/env python3
"""Testes offline do C10, sem acesso ao broker, home real ou PKI."""
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parent.parent / 'scripts'
sys.path.insert(0, str(SCRIPTS))
import fase8_4_5_4c10_indices_versionados as c10

LINK = {'old': '1'*64, 'new': '2'*64, 'c9_sha256':'3'*64}

class C10Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'state' / 'versions'
        self.root.parent.mkdir(mode=0o700)

    def init(self):
        return c10.initialize(LINK, self.root)

    def test_21_exact_requirements(self):
        req = c10.requirements()
        self.assertEqual(len(req), 21)
        self.assertEqual({x['category'] for x in req}, {'lab','bridge','device-sensor02','operacionais'})

    def test_create_and_verify_private(self):
        path = self.init()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        for name in (*c10.DOCS, c10.EVIDENCE, c10.MANIFEST):
            self.assertEqual(stat.S_IMODE((path / name).stat().st_mode), 0o600)
        p, registry = c10.verify_bundle(LINK, self.root)
        self.assertEqual(path, p)
        self.assertEqual(registry['entries'], [])

    def test_no_reinitialization(self):
        self.init()
        with self.assertRaises(c10.Block): self.init()

    def test_link_to_c9_manifest(self):
        self.init()
        other = {**LINK, 'c9_sha256': 'f'*64}
        with self.assertRaises(c10.Block): c10.verify_bundle(other, self.root)

    def test_immutable_plan_tamper_rejected(self):
        d = self.init(); path = d / c10.DOCS[3]
        path.write_bytes(path.read_bytes() + b' ')
        with self.assertRaises(c10.Block): c10.verify_bundle(LINK, self.root)

    def test_manifest_tamper_rejected(self):
        d = self.init(); path = d / c10.MANIFEST
        obj = json.loads(path.read_bytes()); obj['approval'] = 'GRANTED'
        path.write_bytes(c10.encode(obj))
        with self.assertRaises(c10.Block): c10.verify_bundle(LINK, self.root)

    def test_no_evidence_approved(self):
        d = self.init()
        data = json.loads((d/c10.EVIDENCE).read_bytes())
        data['approval'] = 'GRANTED'
        with self.assertRaises(c10.Block): c10.validate_evidence(data, LINK)

    def test_register_metadata_only(self):
        self.init()
        self.assertEqual(c10.append_entry(LINK,'BRI-01','EV-A-ABCDEF','a'*64,'inventario-redigido',self.root),1)
        _, obj = c10.verify_bundle(LINK,self.root)
        self.assertEqual(obj['entries'][0]['review'],'pending-independent-review')
        self.assertEqual(obj['approval'],'NOT_GRANTED')

    def test_duplicate_ref_rejected(self):
        self.init()
        c10.append_entry(LINK,'BRI-01','EV-A-ABCDEF','a'*64,'inventario-redigido',self.root)
        with self.assertRaises(c10.Block):
            c10.append_entry(LINK,'BRI-01','EV-A-ABCDEF','a'*64,'inventario-redigido',self.root)

    def test_no_secret_or_path_refs(self):
        self.init()
        for bad in ('senha-meu-segredo','/tmp/password','EV-A-BAD', 'EV-A-ABCDEF/../../x'):
            with self.subTest(bad=bad), self.assertRaises(c10.Block):
                c10.append_entry(LINK,'BRI-01',bad,'a'*64,'inventario-redigido',self.root)

    def test_wrong_fingerprint_rejected(self):
        self.init()
        fake = {**LINK, 'new':'4'*64}
        with self.assertRaises(c10.Block): c10.verify_bundle(fake, self.root)

    def test_public_permissions_blocked(self):
        d = self.init(); (d/c10.MANIFEST).chmod(0o644)
        with self.assertRaises(c10.Block): c10.verify_bundle(LINK,self.root)

    def test_symlink_document_blocked(self):
        d = self.init(); doc = d / c10.DOCS[0]
        payload = d / 'payload'; payload.write_bytes(doc.read_bytes())
        doc.unlink(); doc.symlink_to(payload)
        with self.assertRaises(c10.Block): c10.verify_bundle(LINK,self.root)

    def test_hardlink_document_blocked(self):
        d = self.init(); doc = d / c10.DOCS[1]
        os.link(doc, d / 'second-link')
        with self.assertRaises(c10.Block): c10.verify_bundle(LINK,self.root)

    def test_revoked_sensor_never_in_c8(self):
        d=self.init(); doc=json.loads((d/c10.DOCS[3]).read_bytes())
        self.assertEqual(doc['pending_count'],21)
        self.assertNotIn('device-sensor01', json.dumps(doc))

    def test_code_has_no_network_or_git_mutation(self):
        text = (SCRIPTS/'fase8_4_5_4c10_indices_versionados.py').read_text()
        for forbidden in ('mosquitto_pub', 'mosquitto_sub', 'git push', 'subprocess.run(', 'socket.create_connection('):
            self.assertNotIn(forbidden, text)

    def test_cli_preflight_requires_gate(self):
        with patch.object(c10,'gate',side_effect=c10.Block('sem C9')):
            self.assertEqual(c10.cli(['preflight']),2)

    def test_readonly_verifier_no_index_change(self):
        d=self.init(); before={p.name: p.read_bytes() for p in d.iterdir() if p.is_file()}
        c10.verify_bundle(LINK,self.root)
        after={p.name: p.read_bytes() for p in d.iterdir() if p.is_file()}
        self.assertEqual(before,after)

if __name__=='__main__': unittest.main(verbosity=2)
