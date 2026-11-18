"""C.9 — testes isolados; nenhuma origem real, broker ou repositorio alterado."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/fase8_4_5_4c9_reconciliacao_baseline.py"
spec = importlib.util.spec_from_file_location("c9", SCRIPT)
c9 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c9)


class C9Tests(unittest.TestCase):
    def setUp(self):
        self.prev = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(os.umask, self.prev)
        self.root = Path(self.temp.name)

    def fixture(self):
        old_manifest = "a" * 64
        old_snapshot = c9.OLD_DEFAULT
        c7 = json.dumps({"snapshot_manifest_sha256": old_manifest}).encode()
        return {
            "c4": json.dumps({"meta": {"snapshot_manifest_sha256": old_manifest}}).encode(),
            "c6": json.dumps({"snapshot_manifest_sha256": old_manifest}).encode(),
            "c7": c7,
            "c8": json.dumps({
                "schema": "rust-server/phase8.4.5.4-c8/evidence-index-v1",
                "baseline": {"snapshot": str(old_snapshot), "c7_path": str(c9.STATE_DEFAULT.parent / c9.FILES["c7"]), "c7_sha256": c9.sha(c7)},
                "scenario": "A", "approval": "NOT_GRANTED", "cutover_8883": "FORBIDDEN",
                "requirements": [f"REQ-{i:02d}" for i in range(21)],
                "evidence": [],
            }).encode(),
        }

    def files(self):
        old = {str(i): b"fixed" for i in range(17)}
        old.update({key: b"old" for key in c9.EXPECTED})
        new = old.copy()
        new.update({key: b"v2" for key in c9.EXPECTED})
        return old, new

    def test_20_exact_expected(self):
        self.assertEqual(c9.changed_labels(*self.files()), c9.EXPECTED)

    def test_unexpected_fourth_difference_blocked(self):
        old, new = self.files()
        new["0"] = b"rogue"
        with self.assertRaises(c9.Block):
            c9.changed_labels(old, new)

    def test_missing_differential_blocked(self):
        old, new = self.files()
        new["lab/pki/server.key"] = b"old"
        with self.assertRaises(c9.Block):
            c9.changed_labels(old, new)

    def test_number_files_bound_to_20(self):
        old, new = self.files()
        old["extra"] = b"bad"
        new["extra"] = b"bad"
        with self.assertRaises(c9.Block):
            c9.changed_labels(old, new)

    def test_history_links_verified(self):
        result = c9.verify_metadata(self.fixture(), "a"*64, c9.OLD_DEFAULT)
        self.assertEqual(set(result), set(c9.FILES))

    def test_bad_c7_hash_blocked(self):
        data = self.fixture()
        c8 = json.loads(data["c8"])
        c8["baseline"]["c7_sha256"] = "0"*64
        data["c8"] = json.dumps(c8).encode()
        with self.assertRaises(c9.Block):
            c9.verify_metadata(data, "a"*64, c9.OLD_DEFAULT)

    def test_reject_c8_approval(self):
        data = self.fixture()
        c8 = json.loads(data["c8"])
        c8["approval"] = "GRANTED"
        data["c8"] = json.dumps(c8).encode()
        with self.assertRaises(c9.Block):
            c9.verify_metadata(data, "a"*64, c9.OLD_DEFAULT)

    def test_reject_changed_c6_fingerprint(self):
        data = self.fixture()
        data["c6"] = json.dumps({"snapshot_manifest_sha256": "b"*64}).encode()
        with self.assertRaises(c9.Block):
            c9.verify_metadata(data, "a"*64, c9.OLD_DEFAULT)

    def test_reject_c8_baseline_changed(self):
        data = self.fixture()
        c8 = json.loads(data["c8"])
        c8["baseline"]["snapshot"] = "arbitrary"
        data["c8"] = json.dumps(c8).encode()
        with self.assertRaises(c9.Block):
            c9.verify_metadata(data, "a"*64, c9.OLD_DEFAULT)

    def test_exclusive_private_state_and_no_overwrite(self):
        where = self.root / "state"
        where.mkdir(mode=0o700)
        path = where / "c9.json"
        c9.create_exclusive(path, {"approval": "NOT_GRANTED"})
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        with self.assertRaises(c9.Block):
            c9.create_exclusive(path, {"approval": "NOT_GRANTED"})

    def test_public_dir_blocked(self):
        where = self.root / "state"
        where.mkdir(mode=0o700)
        where.chmod(0o755)
        with self.assertRaises(c9.Block):
            c9.create_exclusive(where / "c9.json", {})

    def test_public_file_blocked(self):
        path = self.root / "public.json"
        path.write_text("{}")
        path.chmod(0o644)
        with self.assertRaises(c9.Block):
            c9.private_file(path)

    def test_symlink_file_blocked(self):
        file = self.root / "real"
        file.write_text("x")
        file.chmod(0o600)
        link = self.root / "link"
        link.symlink_to(file)
        with self.assertRaises(c9.Block):
            c9.private_file(link)

    def test_no_hidden_approval_in_record(self):
        args = type("A", (), {"old": c9.OLD_DEFAULT, "new": c9.NEW_DEFAULT})()
        f = {"historic_manifest_sha256": "a"*64,
             "current_manifest_sha256": "b"*64,
             "index_sha256": {k: "0"*64 for k in c9.FILES}}
        rec = c9.make_record(args, f)
        self.assertEqual(rec["evidence_count_migrated"], 0)
        self.assertEqual(rec["c_v1_pending"], 21)
        self.assertEqual(rec["approval"], "NOT_GRANTED")
        self.assertEqual(rec["cutover_8883"], "FORBIDDEN")
        c9.validate_record(rec, args, f)
        rec["c_v1_pending"] = 0
        with self.assertRaises(c9.Block):
            c9.validate_record(rec, args, f)

    def stage_file(self, name, mode, payload=b"cert-test"):
        p = self.root / name
        p.write_bytes(payload)
        p.chmod(mode)
        return p

    def test_staging_public_certificate_modes(self):
        for mode in (0o600, 0o640, 0o644):
            p = self.stage_file("ca.crt", mode)
            self.assertEqual(c9.staging_artifact(p), b"cert-test")

    def test_staging_certificate_unsafe_permissions_blocked(self):
        for mode in (0o666, 0o664, 0o755):
            p = self.stage_file("server.crt", mode)
            with self.assertRaises(c9.Block):
                c9.staging_artifact(p)

    def test_staging_key_mode_600_only(self):
        p = self.stage_file("server.key", 0o600, b"secret-not-printed")
        self.assertEqual(c9.staging_artifact(p, key=True), b"secret-not-printed")
        p.chmod(0o644)
        with self.assertRaises(c9.Block):
            c9.staging_artifact(p, key=True)

    def test_staging_symlink_blocked(self):
        p = self.stage_file("ca.crt", 0o600)
        link = self.root / "server.crt"
        link.symlink_to(p)
        with self.assertRaises(c9.Block):
            c9.staging_artifact(link)

    def test_staging_hardlink_blocked(self):
        p = self.stage_file("server.key", 0o600)
        os.link(p, self.root / "other-hardlink")
        with self.assertRaises(c9.Block):
            c9.staging_artifact(p, key=True)

    def test_staging_private_key_class_must_match(self):
        p = self.stage_file("server.key", 0o600)
        with self.assertRaises(c9.Block):
            c9.staging_artifact(p, key=False)

    def test_staging_empty_certificate_blocked(self):
        p = self.stage_file("ca.crt", 0o644, b"")
        with self.assertRaises(c9.Block):
            c9.staging_artifact(p)

    def test_staging_unexpected_filename_blocked(self):
        p = self.stage_file("ca.key", 0o600)
        with self.assertRaises(c9.Block):
            c9.staging_artifact(p)

    def test_no_mqtt_or_mutating_commands_in_source(self):
        src = SCRIPT.read_text()
        self.assertNotIn("subprocess.run(", src)
        self.assertNotIn("mosquitto_pub", src)
        self.assertNotIn("mosquitto_sub", src)
        self.assertNotIn("git push", src)
        self.assertNotIn("os.replace(", src)


if __name__ == "__main__":
    unittest.main(verbosity=2)
