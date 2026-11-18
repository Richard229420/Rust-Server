# Revisao final — Fase 8.3 (Arch Linux)

**Data:** 26/10/2026
**Projeto:** Rust-Server / `services/multiprotocol` (v0.2.2)
**Branch prevista:** `feature/fase8-3-device-security`
**Estado:** funcionalidades principais aprovadas nos testes reais enviados pelo operador; patch complementar revisado offline. GitHub ainda depende de commit/push local.

## Evidencias no Arch Linux

- Rust: 18 testes unitarios aprovados na Fase 8.3; `cargo check --all-targets` aprovado.
- MQTT: ACL 8.2 (7/7) e isolamento de dispositivos (7/7) aprovados, TLS e autenticacao MQTT aprovados.
- TCP/TLS: 5/5 testes de autorizacao aprovados.
- Rotacao de `sensor02`: dispositivo ativo com `rotacoes=1`, autentica e publica com credencial atual.
- Revogacao `sensor01`: teste de login antigo rejeitado, enquanto `sensor02` permaneceu ativo.
- HTTP 8080 e HTTPS 8443: HTTP 200 nos testes apresentados.

Essas evidencias foram executadas pelo operador no Arch, nao reproduzidas neste ambiente.

## Alteracoes desta revisao complementar

1. `scripts/test_phase8_3_devices.sh`: checagem obrigatoria de estado antes dos testes e rejeicao explicitamente identificada no resultado MQTT, em vez de classificar qualquer erro de conexao como revogacao correta.
2. `scripts/gerenciar_dispositivos_fase8_3.py`: valida permissao/propriedade/hardlinks, rejeita o diretorio raiz como symlink, valida metadados malformados e antecipa verificacao de token na revogacao.
3. `tests/test_phase8_3_manager.py`: regressao cobrindo symlink de token e symlink do diretorio.
4. `src/bridge.rs`: remove o SUBSCRIBE duplicado na conexao inicial; o ConnAck controla as assinaturas, inclusive apos reconexao.
5. `docs/FASE8_3_IDENTIDADES_E_REVOGACAO.md`: registra alteracoes e limites.

**Verificacoes neste pacote:** Python offline mock passou; `bash -n` e `py_compile` passaram. **O codigo Rust nao foi recompilado aqui** por ausencia da ferramenta `cargo`; a pequena mudanca de assinaturas em `src/bridge.rs` exige `cargo fmt --check`, `cargo check`, `cargo test` e novo teste real no Arch. Os testes reais da Fase 8.3 anteriores foram aprovados pelo operador.

## Riscos e limitacoes remanescentes

- Sem transacao multi-arquivo em `passwords`, `acl` e `devices.json`; existem snapshots para recuperacao manual.
- Os snapshots preservam hashes antigos e precisam de politicas de acesso e retencao.
- Credenciais `password_file` e ACL `acl_file` exigem reinicio para revogacao completa das conexoes ja estabelecidas.
- Nao ha limite por usuario/dispositivo nem isolamento de `client ID` do MQTT.
- A conta `bridge` e privilegiada e precisa de revisao de menor privilegio.
- Broker somente em `127.0.0.1`; nao expor fora do host por enquanto.
- Nenhum banco SQLite do Debian sera utilizado. Bancos do Arch preservados.

## Marco de fechamento

Considerar a Fase 8.3 encerrada **apos** aplicar este complemento e passar novamente os testes offline e MQTT no Arch; entao revisar o diff e executar commit e push com arquivos explicitamente autorizados. Nao fazer merge na `main` sem validar CI e revisar arquivos sensiveis.
