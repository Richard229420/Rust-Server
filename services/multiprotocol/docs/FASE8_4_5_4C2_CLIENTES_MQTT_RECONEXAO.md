# Rust-Server — Fase 8.4.5.4-C.2 — Clientes MQTT e reconexão controlada

**Estado:** patch incremental de ensaio. Não é migração produtiva. Não é autorização de corte.

## Escopo

A fase valida no Mosquitto Dynamic Security temporário `127.0.0.1:8895` uma política de **dois tipos de cliente**, utilizando apenas identidades fictícias do ensaio:

| Identidade funcional | Client ID no ensaio | Objetivo | Limite |
| --- | --- | --- | --- |
| `lab` | `phase8454c2-cli-a` e `phase8454c2-cli-b` | Demonstrar CLI temporários com IDs diferentes e simultâneos; ACLs de alertas | O login sem vínculo de ID aceita outros IDs desde que a senha seja válida. **Não recomendável reutilizar credencial compartilhada em produção sem avaliação de risco.** |
| `device-sensor02` | `phase8454c2-sensor02` | Exigir vínculo exato de usuário, senha e ID; telemetria/resposta | ID temporário, **não comprovado em dispositivo real** |
| `bridge` | `rust-server-bridge-local` | Recebedor/encaminhador de teste com política equivalente | Nesta fase usa clientes Mosquitto CLI, **não repete o Rust probe da C.1** |
| `device-sensor01` | Nunca provisionado | Rejeição de autenticação | Continua revogado |

**Atenção:** o cadastro `~/.config/rust-server/phase8-4-5-4c/cadastro-prontidao.json` existente exige um ID concreto para cada conta. Este patch **não** o modifica nem o considera preenchido. Antes de marcar os campos de `lab`, será preciso uma decisão específica sobre cliente CLI temporário vs identidade estável/por instância e uma revisão do cadastro pela conversa de Desenvolvimento + Segurança. Os IDs `phase8454c2-*` são proibidos como evidência produtiva.

## Componentes

- `scripts/fase8_4_5_4c2_clientes_mqtt.py`: `inventariar`, `preflight`, `ensaiar`.
- `tests/test_fase8_4_5_4c2_clientes_mqtt.py`: 55 testes offline; nenhuma ligação a brokers.
- Esta documentação e `LEIA-ME-8454C2.txt` no ZIP.

## Pré-requisitos

- Arch Linux, usuário normal, no repositório `~/server/services/multiprotocol` e branch `feature/fase8-4-inventory-dynsec`.
- Scripts anteriores instalados e validados (8.4.5.1–8.4.5.4-C.1, inclusive correção do encerramento de `8895`).
- Snapshot aprovado e **imutável** `/home/arch/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484`.
- Ferramentas: `mosquitto`, `mosquitto_pub`, `mosquitto_sub`, `mosquitto_ctrl`, `ss`; plugin DynSec no caminho já reconhecido nas fases anteriores.
- O comando `preflight` verifica snapshot, baseline ACL/TLS, arquivos originais, plugin e portas temporárias disponíveis. Brokers 8883/8884 não precisam estar iniciados.

## Procedimento seguro no Terminal A

```bash
cd ~/server/services/multiprotocol

unzip -o \
  ~/Downloads/fase8-4-5-4c2-clientes-mqtt-reconexao-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' \
  -d .

python3 -B tests/test_fase8_4_5_4c2_clientes_mqtt.py

SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
python3 -B scripts/fase8_4_5_4c2_clientes_mqtt.py inventariar --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_4c2_clientes_mqtt.py preflight --snapshot "$SNAPSHOT"
```

**Se o preflight apresentar bloqueio, pare e envie somente a mensagem de status, sem imprimir tokens/arquivos de configuração privados.**

Após `APROVADO`:

```bash
python3 -B scripts/fase8_4_5_4c2_clientes_mqtt.py ensaiar --snapshot "$SNAPSHOT"
```

Durante a execução, o script gera senhas aleatórias temporárias em memória; quando necessário, transmite-as para Mosquitto por stdin ou opções em arquivo `0600` privado no scratch `0700` fora do Git. Nunca coloca senhas em `argv` ou saídas normais. Não usa o broker 8883/8884 nem credenciais reais; usa apenas cópias de certificados e políticas do snapshot para compatibilidade de teste. A criação e a rotação ocorrem **exclusivamente no DynSec temporário**.

## Testes operacionais do ensaio

1. Confere DEFAULT DENY, papéis e ACLs equivalentes ao legado, sem contas extras/grupos herdados, excluindo sensor01.
2. Comprova duas conexões CLI `lab` simultâneas com IDs distintos (MQTT 5/TLS e PINGRESP) e comunicação de alertas com a conta de bridge fictícia.
3. Confirma sensor02 com ID vinculado e negação de ID incorreto; valida telemetria de entrada e status de retorno.
4. Exige respostas MQTT 5 explícitas para autenticação falha, publicação e assinatura cruzadas indevidas (não considera timeout sucesso).
5. Para **cada** `lab` e `device-sensor02`: abre sessão, desabilita conta e exige desconexão do cliente ativo, rejeita conexão, reabilita e reconecta.
6. Para **cada** conta: rota senha temporária via stdin, exige rejeição da anterior, estabelece nova conexão e entrega nas duas direções; depois reverte ao segredo de ensaio anterior e valida a entrega novamente.
7. Termina somente o processo Mosquitto iniciado pelo ensaio, aguarda liberação de listeners, remove scratch, revalida snapshot e a situação das portas originais.

## Verificação após ensaio

```bash
python3 -B scripts/fase8_4_5_2_preparar.py verificar --snapshot "$SNAPSHOT"
ss -lntp | rg ':(8883|8884|8895|8896)\b' || true
python3 -B scripts/fase8_4_5_4c_prontidao_corte.py avaliar --snapshot "$SNAPSHOT"
```

`avaliar` pode retornar status não zero por pendências declarativas (**isso é esperado**). O cadastro privado não recebe confirmações automaticamente.

## Critérios e limites

**Aprovado C.2 (isolado)** apenas quando: 55/55 testes Python, preflight, ensaio real e verificação independente do snapshot/listeners passarem.

**Pendente para 8883:** comportamento dos clientes **reais** `lab` e `device-sensor02`, Client IDs efetivos e evidências, distribuição autenticada de credenciais, testes de reconfiguração/retorno nos serviços reais, revisão de risco de CLI compartilhado, janela e monitores/aborto, Git/CI e autorização de Segurança, snapshot final na janela. A Fase 8.4.5.5 não está autorizada.

**Segurança operacional:** nunca execute com `sudo`, nunca altere o `Cargo.toml` principal para este ensaio, nunca reutilize senha de laboratório/produção, não copie senhas ou certificados privados para Git, não reexecute rotinas antigas de provisionamento que reativem `sensor01`, não reinicie os brokers reais. Os módulos auxiliares anteriores são usados apenas com portas temporárias.

**Se falhar:** não repita automaticamente o ensaio. Verifique `ss -lntp | rg ':(8883|8884|8895|8896)\b' || true`, preserve evidências sanitizadas e relate o bloqueio; não mate processos que não pertençam ao ensaio.

## Referência

Mosquitto Dynamic Security: um `clientid` vazio ou ausente permite IDs diferentes com a mesma conta, ao passo que, quando definido, exige usuário + senha + clientid. Veja https://mosquitto.org/documentation/dynamic-security/ . Isso é um recurso técnico, não recomendação de compartilhar credenciais em produção.
