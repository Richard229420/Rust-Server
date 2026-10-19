# Fase 6.3 — Controle de acesso efetivo por papel (RBAC)

## Objetivo

Transformar a politica `auth/policy.rs` definida na Fase 6.1 em verificacao obrigatoria antes de chamar a API SQLite `/api/v1/users`. A identidade e validada usando a sessao opaca da Fase 6.2 **a cada requisicao**, buscando o papel atual e `is_active=1` no SQLite de autenticacao.

## Matriz de permissoes

| Metodo/recurso | viewer | editor | admin |
| --- | --- | --- | --- |
| GET /api/v1/users, GET /api/v1/users/{id} | 200/resultado da API | 200/resultado da API | 200/resultado da API |
| POST /api/v1/users | 403 | permitido | permitido |
| PUT/PATCH /api/v1/users/{id} | 403 | permitido | permitido |
| DELETE /api/v1/users/{id} | 403 | 403 | permitido |

- Sem token, com token malformado, expirado/revogado ou com conta desativada: **401 + WWW-Authenticate: Bearer**.
- Token valido sem papel necessario: **403** JSON, sem revelar recursos.
- Erro interno ao consultar SQLite de autenticacao: **500**, nunca permitir por engano.
- `/health` e os handlers `/api/v1/auth/login`, `/api/v1/auth/me`, `/api/v1/auth/logout` continuam com suas regras anteriores.
- Metodo HTTP desconhecido continua tratado pelo CRUD REST, que devolve **405 + Allow**.
- Contas `auth_accounts` sao diferentes dos registros `api_users`.
- Nenhuma conta admin adicional ou credencial e criada pela instalacao.

## Fluxo de instalacao

1. Interrompa o `cargo run --bin server` e `swagger_lab.py` para liberar portas 8080 e 8765.
2. `bash fase6_3_rbac/instalar_fase63.sh check`
3. `bash fase6_3_rbac/instalar_fase63.sh apply`
4. `cd ~/server && cargo fmt && bash scripts/test_fase63.sh --full`

Os testes de RBAC criam **SQLite temporarios** com contas artificiais `testadmin`, `testviewer` e `testeditor`. Os testes nunca utilizam sua conta `admin` real e abortam caso a porta 8080 esteja ocupada.

## Swagger e explorador offline

Inicie o proxy local com `python3 scripts/swagger_lab.py`, somente em `127.0.0.1:8765`.

- Swagger UI `/docs`: `POST /api/v1/auth/login` permite obter um token; em **Authorize**, cole **somente** o token sem o prefixo `Bearer`. A interface Swagger acrescenta `Authorization: Bearer ...` nas operacoes protegidas.
- Explorador offline `/offline`: digite o token no campo mascarado; ele fica so na memoria da pagina (sem `localStorage`). O retorno de login e exibido na interface; evite compartilhar capturas contendo o token.
- `X-Lab-Token` e protecao do **proxy local**, e **nao** e a credencial da API Rust. O proxy nunca encaminha `X-Lab-Token` ao backend.
- `Authorization` e encaminhado apenas a `/api/v1/users*`, `/api/v1/auth/login`, `/api/v1/auth/me`, `/api/v1/auth/logout`, e sempre para `127.0.0.1:8080`.
- A interface nao deve ser exposta a outros dispositivos nem utilizada em producao. Nao habilite CORS aberto.

## Regressao dos testes antigos

O novo contrato altera intencionalmente o comportamento historico: **o CRUD deixa de ser publico**. Por isso `tests/api_rest.py`, `tests/sqlite_persistence.py` e `tests/auth62_integration.py` (que esperam HTTP 200/201 sem Bearer) nao devem ser usados sem atualizacao; resultados 401 sao agora corretos. A Fase 6.3 entrega sua propria suite fim-a-fim cobrindo operações CRUD autenticadas e negadas, persitencia, revogacao, expiracao, troca de papel e conta desativada.

O mesmo vale para `scripts/validate_openapi.py` e `tests/openapi_contract.py` da Fase 5.3, que propositalmente exigem **seis operacoes sem autenticacao**. Utilize `python3 tests/auth63_openapi_contract.py`, que valida nove operacoes com Bearer/401/403.

## Contas e permissoes reais

A conta administrativa criada na 6.2 permanece valida e podera realizar o CRUD. A criacao de contas `viewer` e `editor` **reais** nao foi exposta por HTTP nesta fase; os testes usam fixtures exclusivamente temporarias. Nao insira contas reais manualmente via SQL sem procedimento seguro de provisionamento. Um comando administrativo dedicado para novas contas podera ser adicionado em refinamento futuro.

## Limitacoes / fases seguintes

- Ainda nao existe limitacao de tentativas de login, bloqueio progressivo ou rate-limit por identidade/IP; previsto para a Fase 6.4.
- HTTP puro e permitido somente no loopback: para cliente externo use HTTPS no Caddy com certificado confiavel.
- Manter backups e nao commitar `data/auth/`, `.sqlite3`, tokens ou senhas.
- Um `git commit` deve incluir OpenAPI JSON **e** YAML e os novos testes.
- O rollback automatico e **conservador**: se `cargo fmt` ou outra alteracao modificar os arquivos apos instalar, o script nao sobrescreve nada automaticamente. Consulte o snapshot em `~/server_backups/fase63_rbac_*` para restauracao manual.
