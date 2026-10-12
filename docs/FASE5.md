# Fase 5 — API REST JSON em Rust

**Projeto:** servidor HTTP/1.1 educacional, com 16 workers, fila limitada, validação estrita HTTP, métricas Prometheus e TLS 1.3 terminado no Caddy.

**Objetivo:** acrescentar uma API REST real sobre o servidor existente, sem substituir rotas HTML, parser TCP, testes das Fases 1–4, Caddy ou arquivos estáticos.

## Rotas

| Método | Endpoint | Resultado | Detalhes |
|---|---|---|---|
| GET | `/api/v1/users` | 200 | Lista paginada: `?limit=20&offset=0` |
| POST | `/api/v1/users` | 201 | Cria usuário; retorna `Location` |
| GET | `/api/v1/users/{id}` | 200 / 404 | Busca por ID |
| PUT | `/api/v1/users/{id}` | 200 / 404 | Substitui nome e e-mail |
| PATCH | `/api/v1/users/{id}` | 200 / 404 | Atualiza parcialmente |
| DELETE | `/api/v1/users/{id}` | 204 / 404 | Exclui, sem corpo |

**Schema de criação/atualização:**

```json
{"name": "Ana Silva", "email": "ana@example.com"}
```

- `name`: string UTF-8 entre 1 e 80 caracteres (após `trim`), sem controles.
- `email`: sintaxe básica ASCII de laboratório, até 254 bytes; armazenado em minúsculas e único, ignorando caixa.
- `id`: inteiro positivo atribuído automaticamente pelo servidor, não pode ser editado.
- `POST` e `PUT`: requerem `name` e `email`; `PATCH` aceita qualquer subconjunto não vazio.
- Campos inesperados, como `id`, `role` e `admin`, são rejeitados.
- Dados em memória (`Arc<RwLock<...>>`), compartilhados entre os 16 workers; **reiniciar o servidor apaga os usuários**.
- Capacidade de até 1.000 usuários, por segurança no laboratório.
- `GET` permite `limit` de 1 a 100 e `offset` inteiro não negativo; padrão `limit=20`, `offset=0`.

### Formato das respostas

**Sucesso (GET/POST/PUT/PATCH):**

```json
{"data":{"id":1,"name":"Ana Silva","email":"ana@example.com"}}
```

**Listagem:**

```json
{"data":[],"pagination":{"total":0,"limit":20,"offset":0}}
```

**Erro estruturado:**

```json
{"error":{"code":"validation_error","message":"name ou email invalido"}}
```

**Códigos de erro:** `400` requisição/JSON inválido, `404` não encontrado, `405` método não permitido (com `Allow`), `409` e-mail duplicado, `411` Content-Length ausente, `413` corpo grande, `415` Content-Type incorreto, `422` dados inválidos, `503` capacidade cheia.

O limite global de requisição da Fase 4 (8.192 bytes) continua valendo. Corpos JSON para a API são limitados a 4.096 bytes, com `Content-Length` obrigatório e `Content-Type: application/json` (opcional `charset=utf-8`). Não há suporte a `Transfer-Encoding: chunked`, keep-alive, pipelining ou 100-continue.

## Instalação incremental

Coloque `fase5_api_rest.zip` em `~/Downloads` e execute:

```bash
cd ~/Downloads
unzip fase5_api_rest.zip
bash fase5_api_rest/instalar_fase5.sh
```

O instalador:

1. Confere a presença de Fase 4 (`src/security.rs`, `src/metrics.rs`).
2. Gera patches de `src/server.rs` e `Cargo.toml`, usando âncoras verificadas (aborta se o formato local divergir).
3. Faz backup dos arquivos alterados em `~/server_backups/fase5_YYYYMMDD_HHMMSS/`.
4. Adiciona `src/api.rs`, `tests/api_rest.py`, `scripts/test_phase5.sh`, `docs/FASE5.md`.
5. Preserva `main.rs`, `request.rs`, `response.rs`, `router.rs`, `security.rs`, `metrics.rs`, Caddy, README e testes anteriores.

Nova dependência Cargo: `serde_json = "1"`; permite decodificar e serializar JSON corretamente. O `Cargo.lock` será atualizado ao executar Cargo. Se o pacote não puder ser baixado devido a configuração de rede, verifique acesso ao `crates.io` e execute novamente `cargo check` após resolver a rede.

## Testar (porta 8080 livre)

Interrompa o Rust (`Ctrl+C`) e, se desejar, o Caddy enquanto os testes iniciam seu próprio backend:

```bash
cd ~/server
cargo fmt
cargo check && cargo test && cargo build --release
python3 tests/integration_http.py --stress
python3 tests/security_http.py
python3 tests/api_rest.py
```

Alternativa: `bash scripts/test_phase5.sh`.

O novo teste de integração tem 21 casos de teste, incluindo concorrência, validação de JSON, rotas antigas, CRUD e Content-Length. Os 61 testes das fases anteriores devem continuar passando. A instalação não executa Cargo ou testes automaticamente; **os resultados devem ser conferidos no Arch do usuário**.

Quando o servidor já estiver rodando, use `python3 tests/api_rest.py --running` (os testes criam e apagam dados fictícios temporários).

## Exercício manual (HTTP local)

Terminal 1:

```bash
cd ~/server
cargo run --release
```

Terminal 2:

```bash
curl -i http://127.0.0.1:8080/api/v1/users
curl -i -X POST http://127.0.0.1:8080/api/v1/users \
  -H 'Content-Type: application/json' \
  -d '{"name":"Ana Silva","email":"ana@example.com"}'
curl -i http://127.0.0.1:8080/api/v1/users/1
curl -i -X PATCH http://127.0.0.1:8080/api/v1/users/1 \
  -H 'Content-Type: application/json' -d '{"name":"Ana Atualizada"}'
curl -i -X PUT http://127.0.0.1:8080/api/v1/users/1 \
  -H 'Content-Type: application/json' -d '{"name":"Bia","email":"bia@example.com"}'
curl -i -X DELETE http://127.0.0.1:8080/api/v1/users/1
```

## Testar por HTTPS (Fase 4 preservada)

Terminal 1: `cargo run --release`.

Terminal 2: `caddy run --config observability/Caddyfile.local --adapter caddyfile`.

Terminal 3:

```bash
curl --cacert "$HOME/.local/share/caddy/pki/authorities/local/root.crt" \
  -i https://localhost:8443/api/v1/users
```

O Caddy deverá encaminhar as rotas `/api/v1/` ao Rust e manter a restrição a `/metrics`; os quatro headers de segurança no proxy continuam sem duplicação.

## Segurança e limitações

- **Sem autenticação/autorização, banco de dados, criptografia de dados em repouso, persistência, auditoria de alterações, rate limiting específico da API ou suporte RFC completo.**
- Utilize somente loopback e dados fictícios; não exponha publicamente nem armazene e-mails/dados pessoais reais.
- Validação de e-mail é intencionalmente simples, não pretende implementar todas as variantes RFC.
- `serde_json::Value` faz parsing JSON; nenhuma validação abrangente de chaves JSON repetidas está implementada.
- Observabilidade da Fase 3 preservada: novos status HTTP da API entram na série `rust_http_responses_total{status="other"}` enquanto não houver extensão do conjunto de status reconhecidos.
- Não há suporte a CORS; acesso via páginas hospedadas em outras origens não é oferecido.

**Próximas evoluções possíveis:** autenticação, persistência SQLite/PostgreSQL, versionamento de schema, documentação OpenAPI, métricas específicas da API, testes de fuzzing e CI/CD.


## Integracao revisada (sem ancorage em handle_connection)

A integracao revisada usa `std::sync::OnceLock<Api>` no `server.rs` para compartilhar uma unica instancia concorrente da API entre os workers existentes, sem mudar o despacho das conexoes nem as assinaturas dos handlers. O estado e em memoria, compartilhado pela duracao do processo.
