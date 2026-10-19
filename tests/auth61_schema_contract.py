#!/usr/bin/env python3
"""Checks SQLite DDL safety using stdlib sqlite3, without running Rust."""
import re
import sqlite3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'src/auth/schema.rs'


def ddl():
    contents = SOURCE.read_text(encoding='utf8')
    match = re.search(r'const SQL_CREATE_SCHEMA: &str = r#"(.*?)"#;', contents, flags=re.S)
    if not match:
        raise AssertionError('Nao foi possivel extrair SQL_CREATE_SCHEMA de schema.rs')
    return match.group(1)


class SchemaContract(unittest.TestCase):
    def setUp(self):
        self.con = sqlite3.connect(':memory:')
        self.con.execute('PRAGMA foreign_keys = ON')
        self.con.executescript(ddl())

    def tearDown(self):
        self.con.close()

    def test_schema_version_and_application_id(self):
        self.assertEqual(self.con.execute('PRAGMA user_version').fetchone()[0], 1)
        self.assertEqual(self.con.execute('PRAGMA application_id').fetchone()[0], 0x52535441)

    def test_no_seeded_accounts_or_sessions(self):
        for table in ('auth_accounts', 'auth_sessions', 'auth_audit_events'):
            self.assertEqual(self.con.execute(f'SELECT count(*) FROM {table}').fetchone()[0], 0)

    def test_roles_constrained(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.con.execute("INSERT INTO auth_accounts(username,password_hash,role) VALUES ('foo','$argon2id$stub','root')")

    def test_plaintext_password_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.con.execute("INSERT INTO auth_accounts(username,password_hash,role) VALUES ('foo','senha123','admin')")

    def test_case_insensitive_identity_uniqueness(self):
        self.con.execute("INSERT INTO auth_accounts(username,password_hash,role) VALUES ('Alice','$argon2id$stub','viewer')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.con.execute("INSERT INTO auth_accounts(username,password_hash,role) VALUES ('ALICE','$argon2id$stub','editor')")

    def test_session_must_reference_account_and_sha256_sized_digest(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.con.execute("INSERT INTO auth_sessions(account_id,token_digest,expires_at) VALUES (5,zeroblob(32),unixepoch()+3600)")
        self.con.execute("INSERT INTO auth_accounts(username,password_hash,role) VALUES ('Alice','$argon2id$stub','viewer')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.con.execute("INSERT INTO auth_sessions(account_id,token_digest,expires_at) VALUES (1,x'0123',unixepoch()+3600)")
        self.con.execute("INSERT INTO auth_sessions(account_id,token_digest,expires_at) VALUES (1,zeroblob(32),unixepoch()+3600)")
        with self.assertRaises(sqlite3.IntegrityError):
            self.con.execute("INSERT INTO auth_sessions(account_id,token_digest,expires_at) VALUES (1,zeroblob(32),unixepoch()+3600)")

    def test_no_plaintext_secrets_columns(self):
        columns = [r[1] for table in ('auth_accounts','auth_sessions','auth_audit_events')
                   for r in self.con.execute(f'PRAGMA table_info({table})')]
        for forbidden in ('password', 'token', 'secret', 'api_key'):
            self.assertNotIn(forbidden, columns)


if __name__ == '__main__':
    unittest.main(verbosity=2)
