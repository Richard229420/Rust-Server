#!/usr/bin/env python3
"""Testes offline da especificacao JSON (somente biblioteca padrao do Python)."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from validate_openapi import check_schema, check_spec, resolve_ref, SpecError  # noqa: E402


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads((ROOT / 'docs/openapi.json').read_text(encoding='utf-8'))

    def test_six_http_operations(self):
        self.assertEqual(check_spec(self.spec), 6)

    def test_json_2020_12_dialect(self):
        self.assertEqual(self.spec['jsonSchemaDialect'], 'https://json-schema.org/draft/2020-12/schema')

    def test_patch_requires_at_least_one_field(self):
        patch = resolve_ref(self.spec, '#/components/schemas/UserPatch')
        self.assertRaises(SpecError, check_schema, self.spec, patch, {}, 'PATCH')
        check_schema(self.spec, patch, {'name': 'Novo Nome'}, 'PATCH')

    def test_post_requires_name_and_email(self):
        create = resolve_ref(self.spec, '#/components/schemas/UserCreate')
        self.assertRaises(SpecError, check_schema, self.spec, create, {'name': 'Ana'}, 'POST')
        check_schema(self.spec, create, {'name': 'Ana', 'email': 'ana@example.com'}, 'POST')

    def test_unexpected_body_properties_rejected(self):
        create = resolve_ref(self.spec, '#/components/schemas/UserCreate')
        self.assertRaises(SpecError, check_schema, self.spec, create, {'name': 'Ana', 'email': 'ana@example.com', 'admin': True}, 'POST')

    def test_response_204_has_no_body(self):
        operation = self.spec['paths']['/api/v1/users/{id}']['delete']
        self.assertNotIn('content', operation['responses']['204'])

    def test_created_response_has_location(self):
        operation = self.spec['paths']['/api/v1/users']['post']
        self.assertIn('Location', operation['responses']['201']['headers'])

    def test_no_undocumented_authentication(self):
        self.assertEqual(self.spec['security'], [])

    def test_bad_reference_is_rejected(self):
        mutated = copy.deepcopy(self.spec)
        mutated['paths']['/api/v1/users']['post']['requestBody']['content']['application/json']['schema']['$ref'] = '#/components/schemas/Invalid'
        with self.assertRaises(SpecError):
            check_spec(mutated)

    def test_removed_operation_is_rejected(self):
        mutated = copy.deepcopy(self.spec)
        del mutated['paths']['/api/v1/users/{id}']['patch']
        with self.assertRaises(SpecError):
            check_spec(mutated)


if __name__ == '__main__':
    unittest.main(verbosity=2)
