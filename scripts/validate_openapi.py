#!/usr/bin/env python3
"""Valida OpenAPI 3.1.1 offline (YAML vs JSON, refs, operacoes e exemplos).

Uso:
  python3 scripts/validate_openapi.py
  python3 scripts/validate_openapi.py --root ~/Downloads/fase5_openapi

Dependencia: PyYAML (Arch: sudo pacman -S --needed python-yaml).
Opcionalmente, valide tambem com um linter externo especializado OpenAPI 3.1.
"""

import argparse
import json
import re
import sys
from pathlib import Path

EXPECTED_METHODS = {
    "/api/v1/users": {"get", "post"},
    "/api/v1/users/{id}": {"get", "put", "patch", "delete"},
}
EXPECTED_RESPONSES = {
    ("/api/v1/users", "get"): {"200", "400"},
    ("/api/v1/users", "post"): {"201", "400", "409", "411", "413", "415", "422", "503"},
    ("/api/v1/users/{id}", "get"): {"200", "400", "404"},
    ("/api/v1/users/{id}", "put"): {"200", "400", "404", "409", "411", "413", "415", "422"},
    ("/api/v1/users/{id}", "patch"): {"200", "400", "404", "409", "411", "413", "415", "422"},
    ("/api/v1/users/{id}", "delete"): {"204", "400", "404"},
}


class SpecError(Exception):
    pass


def ensure(condition, message):
    if not condition:
        raise SpecError(message)


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise SpecError(f"Chave JSON duplicada: {name}")
        result[name] = value
    return result


def resolve_ref(spec, path):
    ensure(isinstance(path, str) and path.startswith("#/"), f"Ref nao-local/invalida: {path}")
    current = spec
    for component in path[2:].split("/"):
        component = component.replace("~1", "/").replace("~0", "~")
        ensure(isinstance(current, dict) and component in current, f"$ref nao encontrada: {path}")
        current = current[component]
    return current


def check_schema(spec, schema, value, location):
    """Verificacao offline das restricoes JSON Schema usadas nos exemplos deste projeto.

    Isto NAO substitui uma validacao completa da OpenAPI Specification.
    """
    if "$ref" in schema:
        return check_schema(spec, resolve_ref(spec, schema["$ref"]), value, location)
    kind = schema.get("type")
    if kind == "object":
        ensure(isinstance(value, dict), f"{location}: objeto esperado")
        fields = schema.get("properties", {})
        for required in schema.get("required", []):
            ensure(required in value, f"{location}: ausente: {required}")
        if schema.get("additionalProperties") is False:
            ensure(set(value) <= set(fields), f"{location}: campos extras")
        ensure(len(value) >= schema.get("minProperties", 0), f"{location}: campos insuficientes")
        for field, item in value.items():
            if field in fields:
                check_schema(spec, fields[field], item, f"{location}.{field}")
    elif kind == "array":
        ensure(isinstance(value, list), f"{location}: array esperado")
        for i, item in enumerate(value):
            check_schema(spec, schema.get("items", {}), item, f"{location}[{i}]")
    elif kind == "string":
        ensure(isinstance(value, str), f"{location}: string esperada")
        ensure(len(value) >= schema.get("minLength", 0), f"{location}: texto curto")
        ensure(len(value) <= schema.get("maxLength", 10**10), f"{location}: texto longo")
        if "pattern" in schema:
            ensure(re.search(schema["pattern"], value) is not None, f"{location}: pattern invalido")
    elif kind == "integer":
        ensure(isinstance(value, int) and not isinstance(value, bool), f"{location}: inteiro esperado")
        ensure(value >= schema.get("minimum", -10**30), f"{location}: menor que minimo")
        ensure(value <= schema.get("maximum", 10**30), f"{location}: maior que maximo")
    if "const" in schema:
        ensure(value == schema["const"], f"{location}: const divergente")


def check_spec(spec):
    ensure(spec.get("openapi") == "3.1.1", "Esperado OpenAPI 3.1.1")
    ensure(spec.get("jsonSchemaDialect") == "https://json-schema.org/draft/2020-12/schema", "Dialeto JSON Schema inesperado")
    ensure(spec.get("security") == [], "API do laboratorio nao tem autenticacao; nao documente auth inexistente")
    ensure(set(spec.get("paths", {})) == set(EXPECTED_METHODS), "Rotas diferentes do contrato Fase 5.2")
    ensure(spec.get("info", {}).get("title") and spec["info"].get("version"), "info incompleto")
    ensure(spec.get("servers"), "servers nao informados")
    op_ids = set()

    def walk(obj):
        if isinstance(obj, dict):
            if "$ref" in obj:
                resolve_ref(spec, obj["$ref"])
            for val in obj.values():
                walk(val)
        elif isinstance(obj, list):
            for val in obj:
                walk(val)
    walk(spec)

    for path, expected_methods in EXPECTED_METHODS.items():
        item = spec["paths"][path]
        found_methods = {name for name in item if name in {"get", "post", "put", "patch", "delete", "options", "trace", "head"}}
        ensure(found_methods == expected_methods, f"Metodos incorretos em {path}: {found_methods}")
        params = list(item.get("parameters", []))
        for method in found_methods:
            operation = item[method]
            op_id = operation.get("operationId")
            ensure(op_id and op_id not in op_ids, f"operationId ausente/repetido: {op_id}")
            op_ids.add(op_id)
            expected = EXPECTED_RESPONSES[(path, method)]
            ensure(expected <= set(operation.get("responses", {})), f"Respostas incompletas: {method} {path}")
            params_all = [resolve_ref(spec, x["$ref"]) if "$ref" in x else x for x in params + operation.get("parameters", [])]
            for path_param in re.findall(r"\{([^{}]+)\}", path):
                ensure(any(x.get("name") == path_param and x.get("in") == "path" and x.get("required") for x in params_all), f"Parametro path {{{path_param}}} sem declaracao")
            if method in {"put", "patch", "post"}:
                body = operation.get("requestBody", {})
                ensure(body.get("required") and "application/json" in body.get("content", {}), f"requestBody JSON ausente: {method}")
            if method == "delete":
                ensure("content" not in operation["responses"]["204"], "DELETE 204 nao deve ter corpo")
            for status, response in operation["responses"].items():
                ensure(re.fullmatch(r"[1-5][0-9][0-9]", status), f"HTTP status invalido: {status}")
                ensure(response.get("description"), f"Descricao ausente: {method} {path} {status}")
                for media in response.get("content", {}).values():
                    if "schema" in media and "example" in media:
                        check_schema(spec, media["schema"], media["example"], f"{method} {path} {status} example")
    for name, schema in spec["components"]["schemas"].items():
        if "example" in schema:
            check_schema(spec, schema, schema["example"], f"components.schemas.{name}.example")
    collection = spec["paths"]["/api/v1/users"]
    success = collection["post"]["responses"]["201"]
    ensure("Location" in success.get("headers", {}), "POST 201 precisa documentar Location")
    limit = resolve_ref(spec, "#/components/parameters/Limit")["schema"]
    ensure(limit.get("minimum") == 1 and limit.get("maximum") == 100 and limit.get("default") == 20, "Paginacao limit divergente")
    offset = resolve_ref(spec, "#/components/parameters/Offset")["schema"]
    ensure(offset.get("default") == 0 and offset.get("minimum") == 0, "Paginacao offset divergente")
    ensure("UserCreate" in spec["components"]["schemas"] and "UserPatch" in spec["components"]["schemas"], "Schemas CRUD ausentes")
    return len(op_ids)


def check_sources(root):
    if not (root / "src/api.rs").exists():
        return False
    checks = {
        "src/api/routes.rs": ['"/api/v1/users"', '"GET, POST"', '"GET, PUT, PATCH, DELETE"', 'MAX_JSON_BODY'],
        "src/api/validation.rs": ['MAX_JSON_BODY: usize = 4_096', 'MAX_PAGE_SIZE: usize = 100', '"name"', '"email"'],
        "src/api/response.rs": ['"error"', '"Location"'] if False else ['"error"', '"Allow"', '"No Content"'],
        "src/api/service.rs": ['"Location"', '"pagination"', '"data"'],
        "src/api/models.rs": ['MAX_USERS: usize = 1_000'],
    }
    for name, needles in checks.items():
        f = root / name
        ensure(f.is_file(), f"Arquivo Fase 5.2 ausente: {name}")
        content = f.read_text(encoding="utf-8")
        for needle in needles:
            ensure(needle in content, f"Contrato da Fase 5.2 mudou em {name}: {needle}")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--sources", action="store_true", help="Tambem comparar sinais do contrato nos modulos Rust")
    args = parser.parse_args()
    root = args.root.resolve()
    try:
        import yaml
    except ImportError:
        print("[ERRO] PyYAML ausente. No Arch: sudo pacman -S --needed python-yaml", file=sys.stderr)
        return 2
    try:
        from_yaml = yaml.safe_load((root / "docs/openapi.yaml").read_text(encoding="utf-8"))
        from_json = json.loads((root / "docs/openapi.json").read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        ensure(from_yaml == from_json, "YAML e JSON divergiram. Nao edite apenas um dos dois.")
        operations = check_spec(from_yaml)
        if args.sources:
            ensure(check_sources(root), "Modulos Rust nao encontrados na raiz informada")
        print(f"[OK] OpenAPI 3.1.1: YAML = JSON; {operations} operacoes, referencias e exemplos validados.")
        if args.sources:
            print("[OK] Sinais relevantes do contrato da Fase 5.2 presentes no codigo Rust.")
        print("[INFO] Validacao estrutural local; para conformidade completa use tambem linter OpenAPI 3.1 especializado.")
        return 0
    except (OSError, json.JSONDecodeError, SpecError, yaml.YAMLError) as error:
        print(f"[FALHOU] {error}", file=sys.stderr)
        return 1

if __name__ == "__main__":
    sys.exit(main())
