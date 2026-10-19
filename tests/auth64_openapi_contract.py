#!/usr/bin/env python3
"""OpenAPI 6.4: nove operacoes RBAC, login 429 e JSON/YAML em sincronia."""
import json
from pathlib import Path
import sys
import yaml

ROOT = Path(__file__).resolve().parents[1]
OPERATIONS = {
    '/api/v1/users': {'get', 'post'},
    '/api/v1/users/{id}': {'get', 'put', 'patch', 'delete'},
    '/api/v1/auth/login': {'post'},
    '/api/v1/auth/me': {'get'},
    '/api/v1/auth/logout': {'post'},
}


def verify():
    spec = json.loads((ROOT/'docs/openapi.json').read_text(encoding='utf8'))
    other = yaml.safe_load((ROOT/'docs/openapi.yaml').read_text(encoding='utf8'))
    assert spec == other, 'JSON e YAML divergentes'
    assert spec['openapi'] == '3.1.1' and spec['info']['version'] == '0.6.4'
    assert spec['security'] == [{'BearerAuth': []}]
    assert spec['components']['securitySchemes']['BearerAuth']['scheme'] == 'bearer'
    assert set(spec['paths']) == set(OPERATIONS), 'Contratos API anteriores alterados'
    for path, methods in OPERATIONS.items():
        assert {name for name in spec['paths'][path] if name in {'get','post','put','patch','delete'}} == methods
        for method in methods:
            response = spec['paths'][path][method]['responses']
            assert '401' in response
            if path.startswith('/api/v1/users'):
                assert '403' in response
    login = spec['paths']['/api/v1/auth/login']['post']
    assert login['security'] == []
    assert '429' in login['responses'], '429 nao documentado'
    assert login['responses']['429']['headers']['Retry-After']['schema']['enum'] == [1, 60]
    assert 'content' not in spec['paths']['/api/v1/auth/logout']['post']['responses']['204']
    print('[OK] OpenAPI 6.4: 9 operacoes, RBAC, JSON/YAML identicos, HTTP 429 + Retry-After')

if __name__ == '__main__':
    try:
        verify()
    except (AssertionError, ValueError, OSError, KeyError) as error:
        print('[FALHOU]', error, file=sys.stderr)
        sys.exit(1)
