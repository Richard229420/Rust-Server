# Rust-Server — Fase 8.4.5.4-C.3

> **AVISO DE BASELINE — 12/11/2026**
>
> Este documento registra procedimentos e resultados da linha de base
> historica da Fase 8.4.5.
>
> Apos a renovacao da PKI v2 em 10/11/2026, foi identificada divergencia
> entre o snapshot de 29/10/2026 e os arquivos de origem atuais.
>
> A Fase C.9 documenta a reconciliacao entre os snapshots historico e
> pos-renovacao, mas nao migra automaticamente os indices privados
> anteriores C.4, C.6, C.7 e C.8.
>
> **Nao reutilizar procedimentos operacionais com o snapshot historico
> presumindo que a linha de base continua valida.**
>
> Consultar C.9 e C.10 e confirmar a reconciliacao vigente antes de
> novas coletas ou registros.
>
> A migracao MQTT da porta 8883 permanece NAO AUTORIZADA.

## Saneamento das pendências de prontidão, sem corte

**Escopo:** o material reduz pendências estritamente comprováveis e oferece o procedimento de coleta e revisão das restantes. Não é uma migração, não inicia/encerra brokers, não faz Git/CI remoto, não captura senhas reais e não aprova segurança. O broker legado `127.0.0.1:8883`, o laboratório `8884` e o snapshot 8.4.5.2 devem permanecer intactos. A fase 8.4.5.5 continua **BLOQUEADA**.

### Situação consolidada

- C.1 — probe de `bridge.rs` com TLS e cliente Rust isolado, aprovado; seu Client ID `rust-server-bridge-local` foi demonstrado em `8895`, **não no processo de produção**.
- C.2 — `lab` com dois Client IDs CLI temporários e `device-sensor02` com ID de ensaio fixo; ACL, disable/enable, rotação/retorno, aprovados em `8895`. **Nenhum cliente real `lab`/sensor02 foi identificado por esse ensaio**.
- C — 24 pendências do modelo privado v1, sendo 6 para cada conta (`lab`, `bridge`, `device-sensor02`) e 6 critérios operacionais. O modelo v1 exige um único ID real por conta, o que é inadequado se a conta `lab` atender vários processos CLI dinâmicos.

### Arquivos desta entrega

- `scripts/fase8_4_5_4c3_evidencias.py`: auditoria, roteiro e registro *explícito* dos três campos conhecidos da bridge.
- `tests/test_fase8_4_5_4c3_evidencias.py`: testes offline de escopo, permissões, segurança do cadastro e fail-closed.
- Este documento e `LEIA-ME-8454C3.txt`.

**Compatibilidade:** não substitui nem modifica `scripts/fase8_4_5_4c_prontidao_corte.py` ou `scripts/fase8_4_5_4c_consolidar.py`, que conferem hashes das fontes previamente revisadas. Não altera `src/`, `Cargo.toml`, `Cargo.lock`, `services`, `.git`, `password_file`, `dynamic-security.json` ou chaves. O novo script só modifica o cadastro privado na ação `registrar-bridge-fonte`.

### Execução no Terminal A (sem sudo)

```bash
cd ~/server/services/multiprotocol
unzip -o ~/Downloads/fase8-4-5-4c3-saneamento-evidencias-sem-corte-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .
python3 -B tests/test_fase8_4_5_4c3_evidencias.py

SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"

python3 -B scripts/fase8_4_5_4c3_evidencias.py \
  auditar --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_4c3_evidencias.py \
  roteiro --snapshot "$SNAPSHOT"
```

Se o cadastro ainda estiver intacto com 24 pendências, a ação abaixo registra somente a **evidência estática** da identidade `bridge` no cadastro existente:

```bash
python3 -B scripts/fase8_4_5_4c3_evidencias.py \
  registrar-bridge-fonte --snapshot "$SNAPSHOT"
```

**Efeito exato:** nos campos da conta `bridge` do arquivo `~/.config/rust-server/phase8-4-5-4c/cadastro-prontidao.json`, preenche (apenas se estiverem vazios ou idênticos):

```json
{
  "client_id": "rust-server-bridge-local",
  "evidence_kind": "application-code",
  "evidence_ref": "src-bridge-rs-92-94"
}
```

Os outros campos da conta e todas as outras identidades e critérios operacionais são preservados, **incluindo `client_id_confirmado: false`**. O arquivo fica privado `0600` em pasta `0700`. O script recusa arquivo inseguro, mudanças simultâneas, dados conflitantes e fonte Rust divergente. Não cria outro cadastro e não muda flags para `true`. **Não execute `modelo` novamente.**

Se o cadastro estava no estado inicial, o total muda de **24 para 21 pendências** (3 da bridge remanescentes, 6 de `lab`, 6 de sensor02 e 6 operacionais). Se houver registros anteriores, a contagem será a real. Isso **não significa** 3 aprovações operacionais: somente 3 campos documentados.

Avalie a situação com as ferramentas anteriores:

```bash
python3 -B scripts/fase8_4_5_4c_prontidao_corte.py \
  avaliar --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_4c_consolidar.py \
  pendencias --snapshot "$SNAPSHOT"
```

O código de saída `3` de `avaliar`/`pendencias` é **esperado** enquanto houver pendências; não representa uma falha no snapshot.

## Como efetivamente fechar as 21 pendências restantes

### Identidade `bridge` (3 campos)

1. **Client ID confirmado:** identificar a instância Rust que é efetivamente executada no ambiente real e conferir se `cfg.mqtt_addr` aponta para `127.0.0.1:8883`; fonte em `src/bridge.rs` e configuração operacional (sem credenciais). O ensaio C.1 não substitui essa verificação.
2. **Cliente suporta troca:** documentar o mecanismo de atualização da variável privada `RUST_SERVER_MQTT_BRIDGE_PASSWORD` no gerenciador de segredos e a necessidade de reinicialização controlada do processo/cliente; validar fora de produção com o **executável/configuração efetivos**.
3. **Retorno legado:** preparar referência restrita à configuração pré-migração e testar retorno da conexão com credencial anterior fora de produção. Não imprimir senhas ou armazená-las no cadastro.

### Identidade `lab` (6 campos + decisão arquitetural)

- Localizar **a implementação real** que usa a conta `lab`: ferramentas CLI, scripts sob gerenciadores de serviços, aplicação ou um operador. Os scripts `test_*` e `diagnosticar_*` só demonstram comportamento de teste.
- **Caso IDs variáveis:** NÃO inventar ID fixo para o cadastro v1. O Dynamic Security aceita Client ID não vinculado; isso permite múltiplas conexões com a mesma conta, mas amplia o risco de credencial compartilhada. Decidir com Segurança se haverá contas separadas por instância, ID estável por processo, ou revisão formal do modelo para modo `dynamic-cli` com inventário por instância e restrições adicionais.
- Se uma conta for dedicada a uma instância real, documentar seu ID efetivo, fonte, evidência de conexão, troca de senha e retorno legado. Se forem múltiplas instâncias, o modelo v1 deve ser revisto **antes** de marcar `client_id_confirmado` como verdadeiro.
- Um registro de código ou da C.2 não é evidência de execução real de `lab`.

### Identidade `device-sensor02` (6 campos)

- Identificar dispositivo físico ou simulador real, serviço/configuração/firmware sob o seu controle, conta usada e Client ID efetivamente enviado ao broker. Não usar `phase8454c2-sensor02` nem `lab84-sensor02`.
- Demonstrar conexão com Client ID estável, tópicos e ACLs esperados, procedimento para instalar credencial nova e reconexão/retorno à credencial legada em laboratório usando a **implementação real do cliente**.
- Confirmar que `sensor01` continua revogado, sem reativar contas ou ampliar ACLs.

### Critérios operacionais (6 campos)

| Campo do cadastro | Evidência necessária para marcar `true` |
|---|---|
| `canal_distribuicao_secreta_definido` | Cofre/entrega autenticada, responsável e acesso mínimo, sem segredos no Git, shell history ou logs |
| `procedimento_rotacao_documentado` | Sequência aprovada: provisionar no candidato, distribuir, reconectar, comprovar MQTT e reverter se falhar |
| `reconfiguracao_cliente_testada_fora_de_producao` | Testes executados com as **implementações reais** de cada cliente e suas configurações alternativas |
| `rollback_reconexao_testado_fora_de_producao` | Evidência de retorno **do lado cliente** a configuração/credencial legada, não somente `8896` |
| `janela_e_responsaveis_definidos` | Janela formal, responsáveis e contatos de emergência; snapshot **final** somente na janela aprovada |
| `monitoramento_e_criterios_aborto_definidos` | Indicadores/limites objetivos de falha: autenticação negada, ausência de alertas/telemetria, reconexões e latência |

**Não marcar critérios concluídos apenas porque C.1/C.2 passaram usando contas fictícias.**

### Coleta local segura, sem imprimir segredos

Pode-se iniciar descobrindo **nomes de serviços**, sem exibir os argumentos de processo nem variáveis de ambiente:

```bash
systemctl --user list-unit-files --type=service --no-pager | rg -i 'rust|mqtt|sensor|bridge' || true
systemctl list-unit-files --type=service --no-pager | rg -i 'rust|mqtt|sensor|bridge' || true

rg -l --hidden -i \
  --glob '!**/*.key' --glob '!**/*.pem' --glob '!**/*.json' \
  --glob '!**/.git/**' --glob '!**/target/**' \
  'device-sensor02|RUST_SERVER_MQTT_ADDR|MqttOptions::new|mosquitto_pub|mosquitto_sub' \
  ~/server ~/.config/rust-server 2>/dev/null || true
```

Essas buscas dão apenas *nomes de arquivos*. Mesmo assim, reveja-os antes de compartilhar. A leitura das configurações reais com autorização e o teste no host da aplicação continuam necessários; não cole conteúdo de arquivos `.env`, opções MQTT privadas, tokens, certificados com chaves ou senhas.

## Aprovações de outros chats e critério de corte

- **Git/CI:** executar auditoria de arquivos sensíveis e histórico, revisão dos novos arquivos, testes CI remoto/PR e registrar aprovação de governança no chat próprio. Nada disso é executado por C.3.
- **Chaves e Segurança:** aprovar política de Client IDs para `lab`, estratégia de credenciais, revogação, distribuição, TLS e rollback; decisão formal no chat de segurança.
- **Operação:** validar clientes reais, janela, responsáveis, observabilidade, critério de aborto e captura/verificação de snapshot final sob autorização.

**Bloqueio permanente desta entrega:** `cutover_authorized=false` e nenhuma operação que modifique `8883`, `8884`, segredos reais ou Git. Cadastro sem pendências não é autorização automática: **a fase 8.4.5.5 deve permanecer não autorizada** até decisões externas e evidência operacional.

### Referências

- [Documentação oficial do Eclipse Mosquitto — Dynamic Security](https://mosquitto.org/documentation/dynamic-security/): Client ID opcional e efeito da vinculação da combinação usuário/senha/Client ID.
- [Manual oficial `mosquitto_pub`](https://mosquitto.org/man/mosquitto_pub-1.html): `-i` define ID; `-I` gera ID a partir de prefixo + PID; sem `-i` o comportamento varia conforme protocolo.
