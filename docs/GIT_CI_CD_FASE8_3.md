# Rust-Server — Git / GitHub / CI — Fase 8.3

## Situacao registrada em 26/10/2026

- Branch de trabalho: `feature/fase8-3-device-security`.
- Rust 1.99.0; servidor HTTP 0.1.0; servico multiprotocolo 0.2.2.
- No laboratorio, MQTT/TLS em 8883, TCP-TLS em 7001, HTTPS em 8443 e HTTP em 8080.
- Testes Rust e isolamento MQTT regulares aprovados, rotacao de `sensor02` aprovada.
- Revogacao REAL de `sensor01` PENDENTE: o comando de revogacao falhou porque o broker estava ativo. O teste `--revoked` subsequentemente falhou.
- Sem confirmacao de commit e push relativos a essa atualizacao. NAO promover a `main` neste estado.

## Fluxo adotado

1. Implementar e testar na branch `feature/fase8-3-device-security`.
2. Corrigir o bloqueio de revogacao REAL no Arch Linux e obter resultado aprovado no teste `--revoked`.
3. Conferir `git status`, `git diff --check`, `git diff --cached` e o scanner de arquivos versionados.
4. Fazer commit(s) pequenos e descritivos, e push apenas depois de conferir o que sera publicado.
5. Abrir PR contra `main`; verificar os tres jobs da CI e revisar evidencias locais higienizadas.
6. Fazer merge somente apos aprovacoes, branch protection e verificacoes reais.
7. Criar tag de lancamento apenas quando houver uma versao liberada; NAO criar tag agora.

### Commits sugeridos (apos aprovacao local)

- `feat(mqtt): isolar identidades de dispositivos na fase 8.3`
- `test(security): validar rotacao e revogacao de dispositivos`
- `ci: adicionar validacoes Rust e auditoria de arquivos sensiveis`

### Branches

- `main`: estavel; nunca misturar alteracoes incompletas de dispositivos.
- `feature/fase8-3-device-security`: atual, em desenvolvimento.
- `fix/*`: correcoes; `hotfix/*`: urgentes; `release/*`: preparacao de release.

## CI executada no GitHub

O workflow `.github/workflows/rust-ci.yml` executa em push para branches conhecidas, PR para `main` e disparo manual:

- `Seguranca - arquivos e testes offline`: auditoria de arquivos rastreados e teste Python do gerenciador (mock/offline).
- `Rust - servidor-http`: rustfmt, cargo check, clippy estrito e cargo test (`Cargo.toml`).
- `Rust - multiprotocolo`: idem para `services/multiprotocol/Cargo.toml`.

Uso de Rust **1.99.0** e `--locked` para respeitar os arquivos Cargo.lock. Nao ignorar os Cargo.lock no Git.

A CI nao abre 8080/8443/7001/8883, nao cria usuarios MQTT reais e nao le chaves, tokens ou bancos locais. Nao ha deploy automatico nesta fase. Se algum teste exigir arquivos secretos locais, ele deve ser adaptado para fixtures efemeras, e nao copiar esses segredos para o GitHub.

## Validacao real de revogacao no laboratorio

No computador Arch Linux:

1. Parar os processos multiprotocolo e Mosquitto que usam as portas 7001, 8443 e 8883 (por exemplo Ctrl+C nos terminais correspondentes).
2. Confirmar que a porta do broker esta livre: `ss -lntp | rg ':8883\b'` (sem saida significa porta nao esta em LISTEN).
3. No diretorio `~/server/services/multiprotocol`, executar `python3 scripts/gerenciar_dispositivos_fase8_3.py revoke sensor01`.
4. Confirmar com `python3 scripts/gerenciar_dispositivos_fase8_3.py list` que `sensor01` esta `revoked` e `sensor02` `active`.
5. Reiniciar o broker: `bash scripts/run_phase8_2_mosquitto.sh` (terminal dedicado).
6. Em outro terminal: `source scripts/env_phase8.sh && cargo run`.
7. Em outro terminal (com `source scripts/env_phase8.sh`), executar `bash scripts/test_phase8_3_devices.sh --revoked sensor01 sensor02`.
8. Exigir aprovacao completa. Nao colar tokens reais em commits, logs de PR ou issues.

Caso haja falha, continuar o desenvolvimento na feature branch; nao marcar a tarefa como concluida.

## Revisao segura antes do commit

Na raiz `~/server`:

```bash
git rev-parse --show-toplevel
git status -sb
git diff --check
git diff --stat
python3 scripts/ci/check_sensitive_files.py
```

Para adicionar somente as mudancas de CI:

```bash
git add .github/workflows/rust-ci.yml .github/pull_request_template.md \
  scripts/ci/check_sensitive_files.py docs/GIT_CI_CD_FASE8_3.md .gitignore
git diff --cached --check
git diff --cached --name-only
python3 scripts/ci/check_sensitive_files.py
```

O scanner confere arquivos **ja rastreados**. Por isso, a revisao de `git diff --cached` e `git status` continua obrigatoria. Para cada arquivo existente e novo da Fase 8.3, adicionar caminhos explicitamente, e nunca usar `git add -A` sem inspecao previa.

Se um arquivo com segredo ja estiver versionado, `.gitignore` nao o remove do indice: investigar o historico, usar `git rm --cached <caminho>` apenas com o caminho confirmado, revogar/rotacionar credenciais vazadas e avaliar saneamento do historico com cuidado.

## Pull Request e protecao de `main`

No GitHub, abrir PR de `feature/fase8-3-device-security` para `main`. Em `Settings > Rules > Rulesets` (ou regra de protecao equivalente):

- Exigir Pull Request e revisao antes de merge, quando houver colaborador disponivel.
- Exigir os checks **`Seguranca - arquivos e testes offline`**, **`Rust - servidor-http`**, **`Rust - multiprotocolo`**.
- Impedir force push e exclusao de `main`.
- Exigir branch atualizada, conforme a politica desejada.

A protecao precisa ser ativada no GitHub por um administrador; adicionar arquivos locais nao a ativa automaticamente. A revisao humana da revogacao real continua sendo criterio adicional. Checkboxes no template de PR, isoladamente, NAO bloqueiam merges.

## Politica de releases e tags

Como o repositório contem crates com versoes distintas, se estiverem juntos no mesmo Git use tags com prefixos (exemplo hipotetico: `multiprotocolo-v0.2.3` ou `server-v0.1.1`). Conferir `git tag -l` e os `Cargo.toml` antes de escolher a proxima versao. A versao 0.2.2 e a versao atual do servico, nao uma autorizacao de lancamento da Fase 8.3.

Somente apos merge e release validada, no commit que realmente representa o lancamento, criar tag anotada e publicar. Nao gerar tags automaticas nem workflow de deploy nesta fase.
