# Fase 6.2 — Autenticacao real (Rust-Server)

## Escopo

Adiciona bootstrap local de **uma** conta administrativa (sem senha padrao), verificacao de senha Argon2id, tokens opacos aleatorios de 256 bits, armazenamento apenas do SHA-256 do token, expiracao padrao de 3600 s, introspeccao via `/me` e revogacao via `/logout`.

**AVISO CRITICO:** CRUD `/api/v1/users` continua PUBLICO nesta fase, deliberadamente, para preservar os testes e desenvolver RBAC na Fase 6.3. Nao expor a porta 8080 ou o proxy publicamente. A camada Swagger antiga tem um token proprio (somente do proxy), que **nao** e um token da API. Nao confundi-los.

## Criacao do administrador (local, sem senha em argv/historico)

Pare o servidor antes de provisionar; primeiro ele deve ter inicializado o SQLite da fase 6.1. Se o arquivo ja existe (apos validacao 6.1), execute:

```bash
cd ~/server
cargo run --bin auth_admin -- bootstrap admin
```

O terminal pedira a senha duas vezes com entrada oculta. Minimo 12 bytes, maximo 128 bytes. O bootstrap recusa uma segunda conta. Somente quem puder executar o utilitario com acesso ao banco privado deve provisionar ou redefinir senhas.

Se estiver criando o banco pela primeira vez, rode o servidor no terminal, interrompa-o e so entao rode o utilitario.

Trocar senha (revoga todas as sessoes dessa conta):

```bash
cargo run --bin auth_admin -- reset-password admin
```

`--password-stdin` existe exclusivamente para testes automatizados; evite colocar segredos no historico do shell.

## Endpoints novos

| Verbo | Rota | Resultado |
|---|---|---|
| POST | `/api/v1/auth/login` | 200 com `access_token`, `token_type`, `expires_in` e `expires_at`; 401 para credenciais invalidas |
| GET | `/api/v1/auth/me` | 200 com `id`, `username`, `role`, `expires_at`; 401 sem Bearer valido |
| POST | `/api/v1/auth/logout` | 204 sem corpo; token revogado; 401 sem Bearer valido |

Exemplo no loopback para desenvolvimento:

```bash
curl -sS -X POST http://127.0.0.1:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  --data '{"username":"admin","password":"DIGITE_SOMENTE_NUM_TESTE_DESCARTAVEL"}'
```

**Nao** coloque senha real em comandos gravados no historico. Para uso manual mais seguro, use ferramentas interativas que nao salvem o corpo ou utilize arquivo temporario restrito, apagado com cuidado. Para trafego real entre maquinas, **somente HTTPS via Caddy**. O HTTP deve ficar no loopback.

A sessao usa token com 64 caracteres hexadecimais (32 bytes aleatorios do SO), retornado **uma vez** no login. O banco recebe apenas SHA-256 do token. Nao registramos token, corpo de login ou senha nos logs da API. `Cache-Control: no-store` e os headers de seguranca anteriores permanecem presentes.

O Argon2id usa parametros 19 MiB, 2 iteracoes, 1 lane; o hash PHC contem sal aleatorio. Senhas nao sao criptografadas reversivelmente.

## Arquivos impactados

- Acrescenta tres modulos `src/auth/{credentials,http,store}.rs` e `src/bin/auth_admin.rs`.
- Acrescenta wrappers a `src/auth.rs` (Fase 6.1 mantida).
- Encaixa despacho de `/api/v1/auth/` antes da API antiga em `src/server.rs` (sem alterar o CRUD).
- Adiciona `argon2`, `rand`, `sha2`, `rpassword` em `Cargo.toml`; Cargo.lock sera atualizado por Cargo.
- Nao muda `src/auth/schema.rs`, `data/users.sqlite3`, `data/auth/auth.sqlite3`, Caddy, OpenAPI ou UI.

## Testes

```bash
cd ~/server
cargo fmt
bash scripts/test_fase62.sh --full
```

O script usa diretorios temporarios para os testes HTTP da Fase 6.2, e executa regressao 6.1 e 5.4 se usar `--full`. A porta 8080 deve estar livre. Nunca passe seu banco real para os testes.

## Pendencias explicitas para 6.3/6.4/6.5

- 6.3: interceptar `/api/v1/users`, aplicar autenticação obrigatória e RBAC (`viewer`, `editor`, `admin`), retornar 401/403, migrar testes legados.
- 6.4: limiter de tentativa de login por identidade e origem, politica de lockout, observabilidade e auditoria, mitigacao de abuso.
- 6.5: OpenAPI 3.1, interface Swagger com Bearer, testes de ponta a ponta com Caddy HTTPS, verificação de CORS/CSRF conforme o cliente usado.

`/api/v1/auth/login` ainda nao tem rate limiting — nao disponibilizar em rede nao confiavel, mesmo atras de HTTPS. Esta fase e adequada somente a laboratorio local.
