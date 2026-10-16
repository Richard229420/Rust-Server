# Fase 5.3 — Documentação OpenAPI 3.1.1

Este refinamento documenta o contrato **já implementado** na Fase 5.2. Não muda o código Rust, o esquema SQLite, as respostas HTTP nem a configuração do Caddy.

## Arquivos

| Arquivo | Finalidade |
| --- | --- |
| `docs/openapi.yaml` | Descrição OpenAPI legível e versionável (fonte de referência). |
| `docs/openapi.json` | Mesma descrição em JSON, para ferramentas que preferem esse formato. |
| `scripts/validate_openapi.py` | Verificador offline de paridade YAML/JSON, `$ref`, rotas, métodos, parâmetros, exemplos e alguns contratos do código Rust. |
| `tests/openapi_contract.py` | Dez testes automatizados do contrato. |
| `scripts/test_fase53.sh` | Validação rápida; `--full` também roda a regressão Rust/HTTP/REST/SQLite. |

## Versão e escopo

A versão do **documento** é `openapi: 3.1.1`, dentro da série 3.1. O campo `info.version: 0.5.3` identifica a evolução desta documentação e **não** altera a versão do binário, que pode continuar sendo `0.1.0` no Cargo.toml.

Contratos descritos:

| Método | Caminho | Sucesso | O que faz |
| --- | --- | --- | --- |
| GET | `/api/v1/users` | `200` | Lista paginada (`limit=20`, `offset=0` por padrão). |
| POST | `/api/v1/users` | `201` + `Location` | Cria usuário. |
| GET | `/api/v1/users/{id}` | `200` | Consulta por ID. |
| PUT | `/api/v1/users/{id}` | `200` | Atualiza nome **e** e-mail. |
| PATCH | `/api/v1/users/{id}` | `200` | Atualiza ao menos um desses campos. |
| DELETE | `/api/v1/users/{id}` | `204` | Exclui e não devolve corpo. |

O contrato JSON utiliza objetos `User`, `UserCreate`, `UserPatch`, `UserEnvelope`, `UserListEnvelope`, `Pagination` e `ErrorEnvelope`.

### Regras reais do servidor

- `name`: texto não vazio após `trim`, até 80 caracteres; caracteres de controle rejeitados.
- `email`: formato ASCII aceito pelo validador da aplicação, até 254 bytes, convertido para minúsculas, único sem diferenciar caixa. **A validação do servidor é mais restritiva que o esquema declarativo; o YAML documenta essas regras por texto.**
- Dados persistidos em SQLite. IDs autoincrementáveis não reutilizados, até 1.000 usuários no laboratório.
- `limit`: inteiro decimal entre 1 e 100; `offset`: inteiro decimal a partir de zero. Repetições ou parâmetros extras são rejeitados.
- Escritas exigem `Content-Type: application/json`, `Content-Length` e corpo JSON de no máximo 4.096 bytes. `charset=utf-8` é permitido.
- As respostas da **camada REST** usam `{"error":{"code":"...","message":"..."}}`. Erros rejeitados pelo parser HTTP antes do roteador ou pelo Caddy podem ter outro corpo.
- Não existe autenticação nem autorização na versão atual. **Use somente em ambiente local e com dados fictícios.**

A especificação foca na API `/api/v1/users`. Os endpoints `/health`, `/metrics`, páginas HTML e as políticas de segurança do proxy continuam existindo, mas não fazem parte deste contrato CRUD.

## Instalar (Arch Linux)

A partir do pacote extraído em `~/Downloads/fase5_openapi`:

```bash
cd ~/Downloads
bash fase5_openapi/instalar_fase53.sh check
bash fase5_openapi/instalar_fase53.sh apply
```

O instalador não sobrescreve arquivos existentes, não mexe em `src/`, não precisa interromper o servidor e cria um snapshot **somente de referência** dos módulos Rust em `~/server_backups/`.

Para verificar:

```bash
cd ~/server
python3 scripts/validate_openapi.py --sources
python3 tests/openapi_contract.py
bash scripts/test_fase53.sh
```

O validador usa PyYAML. Se faltar no Arch:

```bash
sudo pacman -S --needed python-yaml
```

Para regressão completa (com a porta 8080 livre):

```bash
cd ~/server
bash scripts/test_fase53.sh --full
```

O `--full` define um banco SQLite **temporário**, para evitar alterações nos usuários reais do laboratório, e executa os testes de persistência, HTTP, segurança e REST existentes.

## Exemplos de uso

Com o Rust iniciado em `127.0.0.1:8080`:

```bash
curl -i http://127.0.0.1:8080/api/v1/users?limit=20\&offset=0

curl -i -X POST http://127.0.0.1:8080/api/v1/users \
  -H 'Content-Type: application/json' \
  -d '{"name":"Ana Silva","email":"ana@example.com"}'
```

Por HTTPS, com o Caddy em execução e a CA local:

```bash
curl --cacert "$HOME/.local/share/caddy/pki/authorities/local/root.crt" \
  https://localhost:8443/api/v1/users
```

## Como abrir em ferramentas OpenAPI

- Editor compatível com **OpenAPI 3.1**: importe `docs/openapi.yaml` ou `docs/openapi.json`.
- Uma ferramenta como Swagger UI, Redoc ou Scalar pode renderizar a descrição, **mas não está instalada e não foi adicionada ao servidor** neste refinamento.
- O YAML **não** está exposto automaticamente em `https://localhost:8443/openapi.yaml` nem em `/docs`. Esta versão é deliberadamente estática e local.

## Validação e limites

O verificador entregue cobre paridade YAML/JSON, referências internas, seis operações, parâmetros, exemplos e partes relevantes da implementação Rust. **Não comprova conformidade integral com a especificação OpenAPI**. Para uma checagem adicional, rode um linter com suporte a OpenAPI 3.1 em seu ambiente.

As respostas podem diferir em situações de erro de protocolo, limites de requisição globais e comportamento do proxy HTTPS. Não se deve interpretar este documento como uma auditoria de segurança ou garantia de compatibilidade com APIs públicas.

## Próximas evoluções

- Documentação 5.4: opcionalmente hospedar a documentação e uma interface Swagger UI/Scalar atrás do Caddy, com acesso restrito.
- Fase 6: autenticação e autorização reais, para depois documentar `securitySchemes` conforme a implementação.

Referência: https://spec.openapis.org/oas/v3.1.1.html
