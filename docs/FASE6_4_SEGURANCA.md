# Fase 6.4 — Auditoria e proteção contra abusos

## Compatibilidade

Continuação da Fase 6.3 RBAC. O instalador altera **somente código-fonte e documentação OpenAPI**; no `check` não acessa o SQLite. No `apply`, faz um snapshot consistente e privado do SQLite de autenticação (incluindo transações WAL), mas não modifica o banco original. `src/api/`, `Cargo.toml`, `Cargo.lock`, Caddy, os arquivos da interface Swagger e o SQLite REST permanecem intactos; `docs/openapi.json` e `docs/openapi.yaml` passam à versão 0.6.4 com a resposta de login HTTP 429. O banco de autenticação da Fase 6.1 permanece com `PRAGMA user_version=1` e suas três tabelas originais; nenhuma conta, senha ou sessão é apagada pela instalação.

**No primeiro startup da Fase 6.4**, somente registros de `auth_audit_events` com mais de 90 dias são apagados. As contas e sessões NÃO são removidas. Esse procedimento deliberadamente modifica dados de auditoria para aplicar a política de retenção: o `apply` salva um snapshot SQLite de autenticação em `~/server_backups/fase64_*/auth_snapshot.sqlite3` (0600), caso encontre o banco padrão. Se você utiliza um caminho personalizado na aplicação, passe o mesmo `RUST_SERVER_AUTH_DB_PATH` ao instalador e confirme o caminho na saída.

## Defesas

- `POST /api/v1/auth/login` utiliza limitação em memória **antes do Argon2id**:
  - Por nome de conta normalizado (case-insensitive): cinco falhas por janela de 60 segundos, seguidas de bloqueio temporário de aproximadamente 60 segundos. A sexta tentativa recebe `HTTP 429` e `Retry-After: 60`.
  - Por endereço IP **da conexão TCP**: vinte falhas por janela de 60 segundos, e bloqueio temporário de aproximadamente 60 segundos.
  - Limite global de **duas verificações Argon2id simultâneas**; excesso recebe `HTTP 429` com `Retry-After: 1`, para evitar que o cálculo de hash ocupe todos os 16 workers.
  - Até 4096 entradas em memória; antigas entradas são descartadas sob pressão. Se a tabela estiver cheia, novas identidades são rejeitadas para preservar recursos.
  - Os limites de conta/IP são **voláteis** e reiniciam quando o processo é reiniciado. Em produção com múltiplas instâncias, seria necessário armazenar limites em um sistema compartilhado e distribuído.
  - `429` não revela a existência de uma conta. Senhas erradas dentro do orçamento continuam recebendo `401`.
- `401`/`403` do guard RBAC permanecem **fail-closed** e são registrados na tabela `auth_audit_events`, com eventos `auth_rejected`/`access_denied` sem tokens, senha, nome da conta ou IP. O campo account_id pode permanecer NULL em negativas RBAC; melhoria futura pode atribuir contas autenticadas de maneira transacional.
- Eventos de login, logout e erro de credencial continuam auditados pela Fase 6.2. `bootstrap` e `password_reset` agora geram eventos adicionais sem segredos.
- Os limites são calculados usando `TcpStream::peer_addr()`, **nunca** `X-Forwarded-For` fornecido pelo cliente. **Atenção ao Caddy**: quando ele encaminha tudo a `127.0.0.1:8080`, todas as conexões vindas do proxy terão IP `127.0.0.1`; o limite por IP será compartilhado e poderá atingir clientes legítimos. Não confie em cabeçalhos arbitrários para contornar isso. O limite por conta continua individual. Para implantações externas, configure limitação de IP no próprio proxy confiável e depois considere uma política de cabeçalhos confiáveis explicitamente validada.

## Auditoria e retenção

Os eventos são armazenados no SQLite de identidades já existente. Exemplo para consultar **contagens sem informação pessoal**:

```bash
sqlite3 data/auth/auth.sqlite3 'SELECT event_type, outcome, count(*) FROM auth_audit_events GROUP BY event_type, outcome ORDER BY event_type;'
```

Não execute consultas exibindo `auth_sessions.token_digest` ou `auth_accounts.password_hash` em logs públicos. Use o banco de dados apenas com permissões locais `0700`/`0600` e não versione `data/`. O startup remove eventos antigos com mais de 90 dias; em servidores de longa duração, programe reinicializações controladas ou acrescente rotina de manutenção periódica.

## Métricas Prometheus

`GET http://127.0.0.1:8080/internal/security-metrics` responde SOMENTE a conexões TCP cujo peer seja loopback e SOMENTE para GET. **Atenção: se o Caddy encaminhar essa rota genericamente, usuários externos poderão obter as métricas porque o Caddy chega por loopback. Bloqueie essa rota explicitamente no Caddy antes de expor o site.** Métricas são totais acumulados **no processo** e reiniciam com o servidor:

- `rust_server_auth_login_success_total`
- `rust_server_auth_login_failure_total`
- `rust_server_auth_login_limited_total`
- `rust_server_auth_argon2_overload_total`
- `rust_server_auth_rbac_denied_total`
- `rust_server_auth_rejected_total`
- `rust_server_auth_argon2_inflight` (gauge)

Não há rótulos contendo contas, tokens, senhas ou IP. Esse endpoint não faz parte da API pública, não está na allowlist do Swagger Lab e não deve ser exposto pelo Caddy.

## Aplicação e testes

```bash
# Com servidor e Swagger Lab parados
cd ~/Downloads
unzip fase6_4_auditoria_protecao.zip
python3 fase6_4_protecao/tests/auth64_install_selftest.py
bash fase6_4_protecao/instalar_fase64.sh check
bash fase6_4_protecao/instalar_fase64.sh apply
cd ~/server
cargo fmt
bash scripts/test_fase64.sh --full
```

Testes de integração usam bancos isolados em `tempfile.TemporaryDirectory()`, nunca sua conta `admin` real. Se a porta `8080` estiver ocupada, os testes param sem encerrar o processo real. Consulte o caminho do backup no resultado do `apply`.

## Segurança operacional

- Não exponha o backend Rust via HTTP diretamente; permaneça no loopback e use Caddy HTTPS para clientes externos.
- O limite por conta pode bloquear temporariamente um cliente legítimo quando atacantes conhecem seu nome. É um trade-off de disponibilidade; monitorar `429` e aplicar mitigação em proxy.
- Ao reiniciar, limites em memória zeram: trate essa proteção como camada adicional, não como solução única para força bruta distribuída.
- Eventos de negação RBAC são gravados sem um limite de escrita específico por origem; sob ataques volumétricos, o banco de auditoria pode crescer durante o intervalo de retenção. Adicione amostragem/agregação e cotas de disco antes de produção.
- O instalador não aplica regras de firewall nem muda o Caddy ou sua política de TLS. A documentação OpenAPI é atualizada; a interface Swagger continua a carregar essa especificação. Cria um snapshot SQLite de autenticação privado no diretório de backup; trate esse arquivo como sensível e nunca o versione no Git.
- O rollback automático recusa sobrescrever código alterado após a instalação, por exemplo por `cargo fmt`. Use o backup manualmente caso necessário. O rollback de código **não restaura auditoria excluída pela retenção**, portanto guarde snapshots do SQLite com WAL quando necessário.

### Regressão de contrato

O teste antigo `auth63_openapi_contract.py` verifica explicitamente a versão `0.6.3` e ficará desatualizado após esta fase. Utilize `tests/auth64_openapi_contract.py` e `scripts/test_fase64.sh --full`, que verificam a versão `0.6.4`, as nove operações e o novo código `429`.
