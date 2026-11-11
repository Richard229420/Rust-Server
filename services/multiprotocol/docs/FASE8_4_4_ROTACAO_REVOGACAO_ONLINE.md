# Fase 8.4.4 — Rotação e revogação ONLINE no laboratório (Arch Linux)

## Escopo e pré-requisitos

- **ÚNICO alvo mutável:** Mosquitto Dynamic Security em `127.0.0.1:8884`.
- Broker da fase 8.3 em `127.0.0.1:8883` e SQLite **NÃO são alterados**.
- Mosquitto 2.1.2, plugin `mosquitto_dynamic_security.so`, `mosquitto_ctrl`, Python 3.14, Rust/Cargo.
- O laboratório da fase 8.4.2 já está `preparado` e `provisionado`.
- `device-sensor01` e `device-sensor02` são contas *fictícias do laboratório*, com senhas diferentes das contas reais.
- A conta alvo desta demonstração é **somente** `device-sensor01` no laboratório 8884.
- Operações de rotação e desabilitação são feitas por comandos separados de `mosquitto_ctrl` protegidos por TLS. As senhas não são passadas por argv; a senha administrativa fica em um arquivo 0600 temporário e é apagada após o comando.

## Terminais

- Terminal B: `python3 scripts/fase8_4_2_lab.py iniciar` (8884) rodando.
- Terminal C: `bash scripts/run_phase8_2_mosquitto.sh` (8883) rodando, se desejar comprovar coexistência.
- Terminal A: comandos de teste.

## Procedimento completo

No Terminal A:

```bash
cd ~/server/services/multiprotocol
python3 scripts/regressao_fase8_4_4.py before
python3 scripts/fase8_4_4_online.py preflight
```

**ATENÇÃO: esta etapa altera o estado do LAB de forma persistente** e impede a suíte antiga 8.4.2 (que exige `sensor01` ativo). Execute apenas quando os testes `before` passarem:

```bash
python3 scripts/fase8_4_4_online.py apply
```

Informe a senha de `lab84-admin` somente no prompt (não cole aqui, não use `sudo`, `set -x` ou histórico). O script:

1. Confirma autenticidade TLS e acesso ao *broker 8884*.
2. Confirma que o `device-sensor01` não autentica com Client ID de outro sensor.
3. Mantém sessões de `sensor02` e bridge abertas para comprovar continuidade e entrega QoS1.
4. Cria `backup-fase8-4-4/` (privado 0700/0600) com cópia verificada das credenciais e do JSON do plugin. Esta cópia não é restaurada automaticamente.
5. Gera nova senha aleatória para `sensor01`, com arquivo privado `.pending` **antes** de solicitar rotação ao broker.
6. Executa `setClientPassword` com nova senha via stdin, confirma novo CONNACK aceito e antigo explicitamente negado.
7. Substitui atomicamente o `.opts` do `sensor01` e abre nova sessão autenticada, com SUBACK autorizado.
8. Executa `disableClient`; exige o fechamento observável da sessão ativa de `sensor01`.
9. Comprova que novos CONNECT com senha velha **e** nova são negados e que `sensor02` mantém sessão MQTT e entrega de mensagens à bridge, sem reiniciar o broker.
10. Registra `fase8_4_4_state.json` (sem segredos) em diretório privado fora do Git.

Ao final (somente se `apply` foi aprovado):

```bash
python3 scripts/regressao_fase8_4_4.py after
python3 scripts/fase8_4_2_lab.py status
ss -lntp | rg ':(8883|8884)\b'
```

**Não execute `scripts/test_fase8_4_2_isolamento.py` após `apply`:** ele exige sensor01 ativo e deverá falhar intencionalmente.

## Erro durante uma operação

Este ensaio **não é idempotente**: não repita `apply` se existir `~/.config/rust-server/phase8-4-2-lab/fase8_4_4_state.json` (inclusive se contiver `prepared`, `rotation-requested`, `rotation-verified`, `disable-requested`). O bloqueio evita uma segunda rotação imprevisível.

- Se falhar antes de `prepared`, nenhuma solicitação de rotação terá sido emitida pelo script.
- O diretorio privado `backup-fase8-4-4/` contem hashes DynSec antigos e copias de senhas; preservar sob acesso 0700 e nunca compartilhar, commitar ou restaurar enquanto o broker estiver rodando.
- Se houver `prepared`/`rotation-requested`, o broker pode ou não ter recebido a nova senha: arquivo `clients/.sensor01-new-*.pending` guarda uma **credencial privada de recuperação** e **não deve ser publicado**. Faça auditoria manual do estado antes de qualquer nova ação.
- Se houver `rotation-verified`, o novo `.opts` é o segredo atual, mas a revogação ainda não foi comprovada.
- Se houver `disable-requested`, a conta pode já estar desabilitada; **não execute outro disable sem revisar**.
- `completed` só é escrito após negar a reconexão, detectar fechamento da sessão e comprovar que sensor02 continuou publicando e a bridge recebendo.

O script não realiza rollback automático de segurança nem habilita novamente o sensor revogado. Uma recuperação deve ser planejada separadamente com `mosquitto_ctrl` após coletar as evidências. **Não restaure `dynamic-security.json` enquanto o broker estiver em execução**, pois o plugin mantém estado em memória e grava suas atualizações.

## Testes de regressão

`regressao_fase8_4_4.py before` faz:

- testes Python 8.3, 8.4.1, 8.4.2 e 8.4.4;
- verificação de sintaxe Python;
- `cargo fmt --check`, `cargo check --all-targets`, `cargo test --all-targets`;
- seis testes MQTT da fase 8.4.2 enquanto os dois sensores ainda estão ativos;
- preflight não destrutivo da fase 8.4.4.

`regressao_fase8_4_4.py after` repete Python/Rust e exige credencial desabilitada recusada e publicação/entrega reais por `sensor02`.

A regressão completa das portas HTTP 8080, HTTPS 8443, TCP 7001 e MQTT 8883 depende dos processos originais. Com os serviços em execução e `source scripts/env_phase8.sh` no terminal de testes, execute as suites de 8.2 separadamente se disponíveis no Arch:

```bash
source scripts/env_phase8.sh
bash scripts/test_phase8_2_acl.sh
bash scripts/test_phase8_1_tcp_acl.sh
bash scripts/test_phase8_1_mqtt_auth.sh
```

Confirme previamente as versões exatas dos scripts e os serviços HTTP/multiprotocolo ativos. **Não execute rotinas de setup `setup_phase8_2_mosquitto.sh` ou gerenciador 8.3 `init`**, pois a operação pode interferir nas identidades atuais.

## Git e relatório de segurança

Apenas `scripts/fase8_4_4_online.py`, `scripts/regressao_fase8_4_4.py`, `tests/test_fase8_4_4_online.py` e esta documentação podem entrar no commit desta implementação. Nenhuma senha, `.opts`, `.pending`, arquivo JSON do plugin, `.token`, certificado privado, banco SQLite ou snapshot deve ser versionado. A verificação de histórico/staging é feita na conversa Git; o relatório e decisão são feitos na conversa Chaves e Segurança.

## Limitações

- Testado offline neste ambiente; a execução Mosquitto/TLS real deve ser feita no Arch.
- A mudança de senha **não necessariamente encerra uma sessão já autenticada**; `disableClient` é o mecanismo testado para desconectar imediatamente.
- O ensaio exige CONNACK explícito para provar recusa de autenticação. Erros TLS ou de rede são tratados como inconclusivos.
- Sem rollback multi-recurso, sem limite por dispositivo, sem mTLS por dispositivo, sem migração do broker 8883.

## Fontes

- https://mosquitto.org/documentation/dynamic-security/
- https://mosquitto.org/man/mosquitto_ctrl-1.html
- https://mosquitto.org/man/mosquitto_ctrl_dynsec-1.html
