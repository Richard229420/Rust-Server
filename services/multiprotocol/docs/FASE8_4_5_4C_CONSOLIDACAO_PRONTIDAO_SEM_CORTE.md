# Rust-Server — Consolidação da Fase 8.4.5.4-C

**Situação em 03/11/2026:** C.1 e C.2 **aprovadas em laboratório**, com base nas saídas apresentadas no chat. A Fase C está **tecnicamente consolidada, mas com prontidão operacional pendente**. **NÃO AUTORIZA A MIGRAÇÃO REAL DO MOSQUITTO EM `127.0.0.1:8883`.**

Este relatório registra evidências dos testes e preserva os limites de cada prova. Não substitui as auditorias de Segurança, Git/GitHub/CI, nem a conferência dos dispositivos de produção. Não é uma ata de autorização de corte.

## 1. Baseline e proteção

- Branch: `feature/fase8-4-inventory-dynsec`.
- Repositório: `~/server/services/multiprotocol` (Arch Linux).
- Snapshot 8.4.5.2: `$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484`, **20 arquivos**; SHA-256/manifesto/permissões aprovados após o ensaio C.2.
- `8883`: broker Mosquitto legado, ACL + password_file; **sensor01 revogado**. Nunca iniciar, parar, alterar, migrar ou restaurar nesta consolidação.
- `8884`: laboratório Dynamic Security; não interagir com ele nesta consolidação.
- `8895`: somente candidato descartável dos ensaios; liberado ao final. `8896`: somente rollback temporário de ensaios anteriores; liberado ao final.
- A verificação independente final `ss -lntp | rg ':(8883|8884|8895|8896)\b' || true` não retornou listeners no log fornecido.

## 2. Evidências laboratoriais consolidadas

| Subfase | Evidência apresentada pelo usuário | Interpretação aprovada | Limite |
| --- | --- | --- | --- |
| 8.4.5.4-C | 35/35 testes, preflight e plano, cadastro privado criado (0700/0600) | Modelo e controles declarativos implementados | Última avaliação: **24 pendências**; cadastro não preenchido automaticamente |
| 8.4.5.4-C.1 | **47/47** testes Python após as correções ring/liberação de porta; saída final `RESULTADO: C.1 ENSAIO ISOLADO APROVADO` | `bridge.rs` real compilado em cópia temporária, TLS, CONNACK, `MQTT → Bus`, `Bus → MQTT`, disable/enable, rotação/retorno temporário, encerramento | Não valida rotação de credenciais reais nem altera o executável principal |
| 8.4.5.4-C.2 | **55/55** testes Python; saída final `RESULTADO: C.2 ENSAIO DE POLITICAS E RECONEXAO APROVADO` | `lab` CLI com dois IDs temporários, sensor02 vinculado a ID fictício, DEFAULT DENY, negações MQTT 5, telemetria/alertas, desconexão, reconexão, rotação/retorno temporário | Não comprova comportamento dos clientes reais `lab` e `device-sensor02` |
| Verificação final | `APROVADO: SHA-256, permissoes, manifesto e candidato verificados (20 arquivos)` e consulta de portas sem resposta | Integridade do snapshot e encerramento dos ensaios confirmados no momento do log | Um snapshot antigo não substitui snapshot final antes de eventual corte |

**Proveniência:** resultados do terminal **fornecidos pelo usuário**. O comando de consolidação proposto abaixo não executa novamente testes MQTT/Cargo nem gera prova de aprovação CI remota.

## 3. Identidades: confirmado x pendente

| Conta MQTT | Evidência | Situação para produção |
| --- | --- | --- |
| `bridge` | `src/bridge.rs` declara usuário `bridge`, Client ID `rust-server-bridge-local`; C.1 comprovou esse vínculo num broker isolado | Ainda falta confirmar a configuração efetiva do processo de produção e procedimento autorizado de troca/retorno |
| `lab` | Scripts CLI usam Client IDs variáveis; C.2 comprovou coexistência de dois IDs temporários quando a conta não está vinculada a ID | **Necessária decisão documentada**: cliente operacional real, política de IDs por instância ou conta(s) dedicada(s); não cadastrar ID fictício nem declarar ID único se clientes simultâneos o invalidarem |
| `device-sensor02` | C.2 testou `phase8454c2-sensor02` apenas no broker descartável | Client ID real/configuração do sensor não observados; não usar ID de ensaio no cadastro |
| `device-sensor01` | Revogado no legado; ensaios negaram autenticação do revogado | **Não reativar**, não provisionar no candidato produtivo |

**Risco de modelagem:** o cadastro C atual exige um Client ID concreto para cada conta. Se `lab` for uma identidade funcional usada por múltiplos clientes CLI temporários, não o preencha à força com um Client ID inventado ou de um único teste. Requer revisão de arquitetura e de schema aprovada por Desenvolvimento e Segurança antes de concluir a prontidão da conta.

## 4. Pendências do cadastro C

A última execução do usuário de `fase8_4_5_4c_prontidao_corte.py avaliar` registrou **24 pendências**: 6 para `lab`, 6 para `bridge`, 6 para `device-sensor02` e 6 critérios operacionais. Elas **não são reduzidas automaticamente** pelos ensaios C.1/C.2.

Critérios operacionais ainda a documentar e comprovar:

1. Canal autenticado de distribuição e custódia das **novas** credenciais, sem colocá-las no cadastro/Git/logs.
2. Procedimento de rotação com responsáveis, sequência e retorno às configurações legadas.
3. Reconfiguração dos **clientes reais** em um ambiente isolado, incluindo descoberta de seus Client IDs efetivos.
4. Rollback de **clientes** e reconexão autenticada, além do rollback do broker; não basta restaurar `password_file`.
5. Janela autorizada, responsáveis, plano de comunicação e snapshot final consistente.
6. Monitoramento de autenticações negadas, telemetria, alertas, desconexões e critérios objetivos de abortar/reverter.

Aprovações **externas e bloqueantes**, ainda não comprovadas: **Segurança/Chaves** (incluindo revisão de credenciais, revogação, risco de conta CLI compartilhada, aprovação formal); **Git/CI** (revisão de diffs/segredos/histórico, pipeline remoto, commits/PR conforme governança); **prontidão operacional** (evidências verificáveis dos clientes reais, rollback, janela, responsáveis).

## 5. Critério de encerramento

- **Consolidação técnica C (documental):** evidências C.1 e C.2 registradas, snapshot validado e pendências explicitadas — **sim**.
- **Prontidão de corte C:** cadastro completo **com comprovação externa** de Client IDs reais, credenciais/rollback, revisão de arquitetura do `lab`, critérios operacionais e aprovações Git/CI + Segurança — **não**.
- **Fase 8.4.5.5 (corte real):** **BLOQUEADA / NÃO AUTORIZADA**; sem alteração de `8883` até decisão explícita e snapshot final sob janela.

## 6. Nova verificação somente leitura

O pacote de consolidação contém:

- `scripts/fase8_4_5_4c_consolidar.py`: auditoria sem chamadas MQTT, sem início de brokers, sem alteração do cadastro ou do snapshot.
- `tests/test_fase8_4_5_4c_consolidar.py`: 24 testes offline para fechamento seguro e proteção da verificação.
- Este documento, mais instruções resumidas.

O script confere branch, fontes C/C.1/C.2 contra SHA-256 das versões de ensaio, fonte Rust com restrição da porta original, snapshot/políticas originais via módulos existentes, cadastro privado `0700/0600` e estado `LISTEN` das portas por `ss -H -lnt`. Ele **não** verifica diretamente a execução passada: as evidências operacionais foram registradas a partir dos logs fornecidos no chat. Se as fontes divergirem, não reutilizar resultados antigos sem nova revisão.

Execute como usuário comum no **Terminal A**:

```bash
cd ~/server/services/multiprotocol

unzip -o \
  ~/Downloads/fase8-4-5-4c-consolidacao-sem-corte-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .

python3 -B tests/test_fase8_4_5_4c_consolidar.py

SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"

python3 -B scripts/fase8_4_5_4c_consolidar.py \
  consolidar --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_4c_consolidar.py \
  pendencias --snapshot "$SNAPSHOT"
```

- `consolidar` retorna `0` se a **consolidação técnica** for verificada, **mesmo com pendências e corte bloqueado**; retorna `2` se houver inconsistência.
- `pendencias` retorna `3` se restarem pendências declaratórias (esperado); `0` se estiverem preenchidas, **sem autorizar o corte**; `2` se houver inconsistência.
- Nenhum comando desta consolidação inicia/paralisa `8883` ou `8884`, grava senhas, altera credenciais, marca campos do cadastro ou executa CI.
- Não execute `modelo` novamente (cadastro já existe) e não use `sudo`. Se surgir BLOQUEIO, não execute `ensaiar` por reflexo e não restaure backups reais.

## 7. Encaminhamento para as conversas próprias

- **Desenvolvimento Rust (aqui):** definir política de Client IDs reais para `lab` e sensor02; mecanismo de provisionamento/distribuição e retorno do lado dos clientes; revisão do schema C caso `lab` use IDs dinâmicos.
- **Chaves e Segurança:** avaliar a estratégia de credenciais, risco de uso compartilhado, confidencialidade, revogação e emitir decisão formal documentada.
- **Git/GitHub/CI:** revisão dos scripts/documentos novos, testes remotos, PR/merge e governança; não realizar comandos de escrita Git nesta consolidação.

**Resultado final:** documentação técnica concluída com evidências laboratoriais; prontidão operacional ainda pendente; **corte real `8883` bloqueado**.
