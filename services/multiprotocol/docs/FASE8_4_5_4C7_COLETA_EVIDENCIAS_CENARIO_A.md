# Rust-Server — Fase 8.4.5.4-C.7

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

## Objetivo e limites

**Cenário A é o operacional principal; Cenário B permanece laboratório/homologação.** Esta fase coleta *pistas locais e evidências estáticas* do host onde o coletor for executado, e produz um registro **privado, sem sobrescrita** para revisão posterior. **Não executa ensaios MQTT e não comprova execução operacional ou implantação remota.**

A Fase C.7 exige as implementações já aprovadas das fases C-v1/C.3, C.4, C.5 e C.6 e verifica o snapshot privado imutável da Fase 8.4.5.2. A C.7 **não cria nem atualiza** `cadastro-prontidao.json` (C-v1), `classificacao-clientes-c4.json` (C-v2) ou `evidencias-operacionais-c6.json` (C.6). O total de **21 pendências deve permanecer aberto**; se o estado divergir, a coleta bloqueia para revisão manual. Não autoriza migração para `8883`.

## O que é efetivamente coletado

| Identidade | Sinais locais capturados | O que **não** é comprovado |
|---|---|---|
| `bridge` | ID encontrado na fonte Rust previamente revisada; presença dos **nomes** das variáveis de configuração; contagem de processos com nome exato `multiprotocol` | Que o processo usou aquela configuração, conexão TLS real, cliente ativo em `8883`, troca/retorno de credenciais |
| `lab` | Existência de dois scripts CLI, presença do nome da variável `RUST_SERVER_MQTT_LAB_PASSWORD`, contagem de `mosquitto_pub/sub` | Identidade de operador, Client ID real, ACL ou autenticação de produção |
| `device-sensor02` | Existência do script de ensaio de dispositivo e estado declarativo C-v2 | Dispositivo real, firmware, host remoto, Client ID operacional, reconexão ou não implantação |
| Todas | Contagem de referências previamente **indexadas** no C.6, sem ler/exibir essas referências, e a declaração de implantação A/B da C.4 | Autenticidade das evidências, aprovação independente ou escopo aprovado de corte |

O script inspeciona os **nomes** de variáveis do arquivo `scripts/env_phase8.sh` usando o leitor já implementado na C.6; o arquivo pode conter segredos. Seus bytes são lidos em memória para detectar nomes, mas **nenhum valor é impresso ou persistido** pela C.7. A inspeção de processos utiliza apenas `/proc/<PID>/comm`, não `/proc/<PID>/cmdline` nem `/proc/<PID>/environ`. Não abre conexões de rede ou MQTT nem consulta bancos SQLite. **O preflight verifica a integridade do snapshot privado da Fase 8.4.5.2**, o que envolve ler arquivos confidenciais do próprio snapshot para calcular hashes; seu conteúdo não é exibido nem incluído no relatório C.7.

A C.7 **não deve ser executada com `sudo`**. O único arquivo gravado será:

```text
~/.config/rust-server/phase8-4-5-4c/coleta-passiva-c7.json
```

O arquivo fica sob diretório privado `0700`, com modo `0600`; é criado em modo exclusivo (`O_EXCL`) e **não é sobrescrito**. Este é um artefato de evidência local, **não é substituto do snapshot** de 20 arquivos, da auditoria de Segurança, de Git/CI ou do snapshot final sob manutenção.

## Terminal A — sequência obrigatória

**A partir da raiz do crate:**

```bash
cd ~/server/services/multiprotocol
pwd

unzip -o \
  ~/Downloads/fase8-4-5-4c7-coleta-evidencias-cenario-a-sem-corte-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' \
  -d .

python3 -B tests/test_fase8_4_5_4c7_coleta_evidencias.py
```

**A suíte tem 62 testes offline.** O resultado esperado é `Ran 62 tests` e `OK`.

```bash
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"

python3 -B scripts/fase8_4_5_4c7_coleta_evidencias.py \
  preflight --snapshot "$SNAPSHOT"
```

Se o preflight for aprovado, criar a coleta **uma única vez**:

```bash
C7="$HOME/.config/rust-server/phase8-4-5-4c/coleta-passiva-c7.json"
if test -e "$C7" || test -L "$C7"; then
    echo 'C.7 ja existente: nao sobrescrever, executar verificar'
else
    python3 -B scripts/fase8_4_5_4c7_coleta_evidencias.py \
      coletar --snapshot "$SNAPSHOT"
fi
```

Validar o registro e apresentar somente resumo sem segredos:

```bash
python3 -B scripts/fase8_4_5_4c7_coleta_evidencias.py \
  verificar --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_4c7_coleta_evidencias.py \
  resumo --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_4c7_coleta_evidencias.py \
  roteiro --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_4c_prontidao_corte.py \
  avaliar --snapshot "$SNAPSHOT"
```

**Nota:** `avaliar` da C-v1 pode retornar código `3` por pendências. Isso é esperado; não é aprovação do corte. Não execute `registrar-bridge-fonte` da C.3 novamente.

## Evidências reais — próximas atividades com revisão independente

O registro C.7 é um dossiê *passivo inicial*. Para cada cliente operacional do **Cenário A** (se implantado), a comprovação real continua dependendo de documentos previamente examinados e **redigidos**, fora do repositório e fora do chat, com custódia e revisão:

- **Bridge:** host/instância e processo/serviço real, identificação do binário, endereço TLS e Client ID efetivo, evidência de troca/retorno em ambiente isolado. Não executar ou expor `ps -ef`, `cmdline`, `environ`, senhas, tokens ou linhas completas de configuração.
- **`lab`:** identificar operadores/instâncias autorizados, determinar uso em A, obter decisão de Segurança sobre IDs dinâmicos versus contas separadas e ACL mínima. Não inventar Client IDs.
- **`device-sensor02`:** comprovar dispositivo real ou a não implantação mediante inventário autorizado; se houver cliente, comprovar sua configuração, mecanismo de atualização e reconexão após rollback. Não confundir o script C.2 com implantação.
- **Operação:** plano seguro de credenciais, canal autenticado, custodiante, testes de rollback por cliente, responsáveis, janela, monitoramento e gatilhos de aborto, snapshot final na janela autorizada.

Caso existam documentos redigidos e revisados, usar **separadamente** a ação `registrar` da C.6 para indexar apenas uma referência opaca permitida e o SHA-256 do **documento redigido**, sem carregar conteúdo nem classificar como aprovado. Exemplo *apenas estrutural* (não executar sem documento real):

```text
python3 -B scripts/fase8_4_5_4c6_inventario_operacional.py \
  registrar --snapshot "$SNAPSHOT" \
  --identidade bridge --tipo runtime-redacted \
  --referencia EvidenciaBridgeAprovacaoPendente \
  --sha256 <sha256-do-documento-ja-redigido>
```

O hash por si só não comprova autenticidade, implantação ou autorização. **A C.7 não insere automaticamente referências no C.6** porque o material passivo produzido não é comprovante suficiente do cliente real.

## Política de segurança inalterada

- `device-sensor01` permanece **revogado**, sem reabilitação no A/B.
- **Nenhuma alteração** de broker `8883`/`8884`, ACL, DynSec, certificados, credenciais ou snapshots.
- **Nenhum** `git add`, commit, merge, push ou alteração de CI; auditoria Git/CI fica no chat próprio.
- **Nenhuma aprovação** externa é sintetizada pelo script, mesmo se as 21 pendências vierem a ser encerradas legitimamente em fases posteriores.
- A migração real da 8.4.5.5 permanece **não autorizada**.
