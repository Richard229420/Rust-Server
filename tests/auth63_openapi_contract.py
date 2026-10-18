#!/usr/bin/env python3
"""Validacao offline do contrato RBAC 6.3 (sem rede)."""
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
METHODS = {
    '/api/v1/users': {'get','post'},
    '/api/v1/users/{id}': {'get','put','patch','delete'},
    '/api/v1/auth/login': {'post'},
    '/api/v1/auth/me': {'get'},
    '/api/v1/auth/logout': {'post'},
}


def ensure(test, msg):
    if not test:
        raise AssertionError(msg)


def all_refs(obj):
    if isinstance(obj, dict):
        if '$ref' in obj:
            yield obj['$ref']
        for value in obj.values():
            yield from all_refs(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from all_refs(value)


def deref(document, ref):
    ensure(ref.startswith('#/'), f'Referencia externa nao permitida: {ref}')
    item = document
    for key in ref[2:].split('/'):
        key = key.replace('~1','/').replace('~0','~')
        ensure(isinstance(item, dict) and key in item, f'Referencia quebrada: {ref}')
        item = item[key]
    return item


def main():
    try:
        import yaml
    except ImportError:
        raise AssertionError('PyYAML ausente. Arch: sudo pacman -S --needed python-yaml') from None
    json_spec = json.loads((ROOT / 'docs/openapi.json').read_text(encoding='utf8'))
    yaml_spec = yaml.safe_load((ROOT / 'docs/openapi.yaml').read_text(encoding='utf8'))
    ensure(json_spec == yaml_spec, 'OpenAPI JSON/YAML divergiram')
    spec = json_spec
    ensure(spec['openapi'] == '3.1.1', 'Versao OpenAPI invalida')
    ensure(spec['info']['version'] == '0.6.3', 'Versionamento esperado 6.3')
    ensure(spec['security'] == [{'BearerAuth': []}], 'Politica Bearer nao obrigatoria por padrao')
    ensure(spec['components']['securitySchemes']['BearerAuth']['scheme'] == 'bearer', 'Esquema Bearer invalido')
    ensure(set(spec['paths']) == set(METHODS), 'Paths ausentes ou extras')
    operation_ids = set()
    for path, methods in METHODS.items():
        actual = {key for key in spec['paths'][path] if key in {'get','post','put','patch','delete','head','options'}}
        ensure(actual == methods, f'Metodos inconsistentes: {path}')
        for method in methods:
            op = spec['paths'][path][method]
            ensure(op['operationId'] not in operation_ids, 'operationId duplicado')
            operation_ids.add(op['operationId'])
            ensure('401' in op['responses'], f'401 nao documentado: {method} {path}')
            if path.startswith('/api/v1/users'):
                ensure('403' in op['responses'], f'403 nao documentado: {method} {path}')
                ensure('security' not in op, f'CRUD permite sobrescrever Bearer: {method} {path}')
            if path == '/api/v1/auth/login':
                ensure(op['security'] == [], 'Login nao deve exigir token')
                ensure('requestBody' in op, 'Login sem corpo')
            if method == 'delete' or path == '/api/v1/auth/logout':
                ensure('content' not in op['responses']['204'], 'HTTP 204 nao pode ter corpo')
    for ref in all_refs(spec):
        deref(spec, ref)
    ensure('Authorization' not in str(spec.get('components', {}).get('parameters', {})),
           'Nao documentar tokens fixos em parametros')
    print(f'[OK] OpenAPI 6.3: JSON/YAML identicos, {len(operation_ids)} operacoes, Bearer/401/403 e refs validos')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, AssertionError) as exc:
        print('[FALHOU]', exc, file=sys.stderr)
        sys.exit(1)
