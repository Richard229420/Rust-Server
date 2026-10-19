# Fase 6.1 — Fundamentos de identidade e autorizacao (laboratorio)

## Escopo exato

Esta fase define **identidades**, papeis e o esquema de armazenamento de credenciais/sessoes para evolucao nas fases 6.2 e 6.3. **Ainda nao implementa login, tokens, middleware de autenticao nem RBAC nas rotas HTTP**. A API `/api/v1/users` permanece acessivel como na Fase 5.4. Nao exponha a API a redes nao confiaveis.

## Por que usar banco SQLite separado?

`data/users.sqlite3` e o cadastro de usuarios da API REST, com `PRAGMA user_version = 1`. Muda-lo nesta etapa quebraria o contrato/testes da Fase 5 e confundiria usuarios de negocios com identidades de seguranca.

Em vez disso, a Fase 6.1 adiciona `data/auth/auth.sqlite3`, com esquema independente versionado em `PRAGMA user_version = 1` e `PRAGMA application_id = 1381192769` (RSTA). O banco de cadastro nao sofre migracao e seus dados sao preservados. A nova base e criada no primeiro `Server::new()`, antes do bind TCP. Em Linux, a pasta privada `auth/` exige `0700` e o arquivo exige `0600`. Um arquivo existente com permissoes amplas, um link simbolico ou um esquema desconhecido impede o startup.

Quando `RUST_SERVER_DB_PATH` aponta para um banco de teste, o banco auth e criado no subdiretorio `auth/` ao lado dele. Pode-se apontar explicitamente com `RUST_SERVER_AUTH_DB_PATH`, usando um diretorio previamente existente e privado ou um caminho `.../auth/auth.sqlite3` cuja pasta mae `.../auth` possa ser criada. A pasta imediatamente superior a `auth` precisa existir.

## Esquema v1 (auth)

- `auth_accounts`: username unico (case-insensitive), hash Argon2id obrigatorio (prefixo apenas como protecao basica de esquema), papel `viewer|editor|admin`, flag de ativacao. Nenhuma conta ou senha padrao e criada.
- `auth_sessions`: digests de token (32 bytes), vencimento e revogacao, integridade referencial. Nenhuma sessao real e emitida nesta fase.
- `auth_audit_events`: prepara registro de eventos sem incluir colunas para senhas/tokens. A instrumentacao sera implementada posteriormente.

**Limitacao:** a constraint de prefixo `$argon2id$` nao valida os parametros criptograficos nem verifica o hash. A autenticacao Argon2id, a geracao de tokens e o armazenamento de digests de fato entram na 6.2. Nao insira contas reais diretamente pelo SQLite.

## Modelo de ameacas (escopo do laboratorio)

| Ameaca | Estado na 6.1 | Proxima protecao |
| --- | --- | --- |
| Roubo de token | Nenhum token emitido | Tokens aleatorios, digest, expiracao e revogacao na 6.2 |
| Forca bruta no login | Nenhum login disponivel | Limitacao de tentativas e observabilidade nas 6.2/6.4 |
| Escalada de privilegios | Papeis definidos, **nao impostos por HTTP** | Middleware deny-by-default em todas as rotas na 6.3 |
| Vazamento do banco | Diretorio/arquivo privado; no gitignore | Backups cifrados e politicas de acesso do host |
| Confianca em proxy/cabecalhos | Nenhuma identidade inferida de headers proxy | Validacao rigorosa do bearer token na 6.2 |
| Credenciais em log | Nenhum fluxo de senha/token nesta fase | Redacao explicita de logs e auditoria na 6.4 |

## Politica planejada (nao aplicada ao HTTP ainda)

| Operacao | viewer | editor | admin |
| --- | --- | --- | --- |
| Listar/consultar usuarios | sim | sim | sim |
| Criar usuario | nao | sim | sim |
| Atualizar usuario | nao | sim | sim |
| Excluir usuario | nao | nao | sim |
| Administrar credenciais | nao | nao | sim |

Um acesso anonimo devera gerar HTTP 401 quando middleware for instalado; conta desativada ou papel insuficiente devera gerar HTTP 403. A politica deny-by-default e testada agora como **funcao Rust**, mas ainda nao protege o roteamento REST.

## Validacao

1. Pare o Rust e o proxy de interface para liberar a porta 8080.
2. `bash scripts/test_fase61.sh --full` a partir da raiz `~/server`.
3. Os testes criam bancos temporarios; os SQLite reais nao devem ser modificados pela regressao.
4. Para inspecionar somente tabelas: `sqlite3 data/auth/auth.sqlite3 '.tables'` (instale `sqlite` se necessario).

Nao envie `data/` ou quaisquer bancos para o Git. Garanta `data/`, `*.sqlite3*`, `__pycache__/` e `*.pyc` no `.gitignore`.

## Falhas seguras e backup

O instalador modifica somente `src/server.rs` e adiciona `src/auth.rs`, `src/auth/`, documentacao e scripts de teste. O `apply` cria um backup em `~/server_backups/fase61_auth_*`. O `rollback` recebe o caminho do backup e so remove arquivos idênticos aos instalados, restaurando `server.rs` se ele nao tiver sofrido outras alteracoes. **Bancos SQLite nunca sao apagados automaticamente.**

## Fases seguintes

- **6.2**: bootstrap administrativo explicitamente iniciado pelo operador, Argon2id, login, token opaco, hash SHA-256 para identificacao de sessao, expiracao e revogacao, limites de tentativa. Logs sem segredos.
- **6.3**: aplicar `authorize` em todas as operacoes REST (incluindo a interface Swagger/offline); respostas 401/403, permissao minima, testes de identidade desativada e operacoes proibidas.
- **6.4**: auditoria e testes de abuso, retencao e higienizacao de logs.
- **6.5**: documentacao OpenAPI e regressao de ponta a ponta.
