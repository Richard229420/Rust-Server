# Rust-Server — Fase 8.4.5.4-C.4

## Cadastro adaptativo de clientes MQTT: A operacional / B laboratório

**Estado:** implementação proposta e testes offline. A aprovação no Arch Linux só poderá ser declarada após executar os testes e os comandos de leitura/criação abaixo no host. **Fase 8.4.5.5 — corte real para 8883 continua bloqueada.**

### Objetivos e premissas

1. **A (principal):** arquitetura para dispositivos físicos e serviços MQTT operacionais. Não declarar que já há cliente real implantado sem evidência. A bridge Rust tem Client ID `rust-server-bridge-local` comprovado no código e em laboratório, mas o processo operacional não foi observado. `device-sensor02` é planejado como cliente persistente com Client ID fixo, sem Client ID efetivo confirmado. A conta `lab` é CLI, com política para produção **pendente de Segurança** (proposta de identidade dedicada por instância ou IDs variáveis sob avaliação).
2. **B (complementar):** scripts CLI e dispositivos de ensaio isolados; `lab` usa IDs temporários/dinâmicos; `bridge` e `device-sensor02` podem ser simulados com IDs fixos temporários. Os ensaios C.1/C.2 foram previamente aprovados, mas não comprovam clientes reais no cenário A.
3. **Revogação:** `device-sensor01` continua fora dos dois cadastros e não deve ser habilitado ou provisionado.
4. **Não alterar o registro C-v1:** ele já contém a evidência estática da bridge (C.3) e **21 pendências** na última avaliação. O novo cadastro C-v2 **não remove, resolve ou reinterpreta nenhuma pendência C-v1**. Seu papel é documentar as hipóteses de implantação e organizar a coleta de evidências.

### Arquivos de entrega

- `scripts/fase8_4_5_4c4_classificacao.py`: preflight, criação exclusiva, matriz e declarações controladas.
- `tests/test_fase8_4_5_4c4_classificacao.py`: 44 testes offline sem brokers.
- `docs/FASE8_4_5_4C4_CLASSIFICACAO_CLIENTES_A_B_SEM_CORTE.md`: este documento.
- `LEIA-ME-8454C4.txt`: instalação e requisitos.

**Não substitui nem modifica** `fase8_4_5_4c_prontidao_corte.py`, `fase8_4_5_4c_consolidar.py`, `fase8_4_5_4c3_evidencias.py`, `src/`, certificados, credenciais, Mosquitto, ACLs, snapshots e arquivos `.git`. Em particular, as fontes revisadas por SHA-256 na consolidação C permanecem intactas. Todos os comandos do novo script verificam branch, snapshot, origens e registro C-v1 antes de qualquer escrita.

### Modelo C-v2 (complementar, não substitutivo)

Caminho privado, fora do repositório:

`~/.config/rust-server/phase8-4-5-4c/classificacao-clientes-c4.json`

A pasta já existente deve estar `0700`; o arquivo novo é criado como `0600`, sem sobrescrever caso exista. A classificação contém `schema=2`, `phase=8.4.5.4-C.4`, `snapshot_manifest_sha256`, `cutover_authorized=false`, três *gates* fixos em `false` (`security`, `git_ci`, `operational_readiness`), e as matrizes A/B das contas conhecidas.

Cada identidade possui `client_class`, `client_id_policy`, `deployment`, `evidence_kind`, `evidence_ref`. Os valores iniciais de `deployment` são sempre `unknown` nos dois cenários. Cadastrar uma **declaração** posterior não equivale a observação real nem a aprovação operacional. O script recusa `cutover_authorized=true`, aprovações externas, contas adicionais, IDs provisórios afirmados como produção, estruturas fora do esquema, permissões indevidas e arquivos linkados.

| Identidade | A: operacional principal | B: laboratório complementar |
|---|---|---|
| `bridge` | persistente, ID fixo no código; implantação desconhecida | persistente, ID fixo; homologação prévia C.1 |
| `lab` | CLI, política de ID pendente de Segurança | CLI, IDs dinâmicos de ensaio C.2 |
| `device-sensor02` | persistente, ID fixo a comprovar | persistente, ID de ensaio C.2 |

Uma proposta futura para `lab` **em A** pode ser registrada como `fixed-per-instance-proposed` ou `dynamic-cli-proposed`, **sem aprovação de Segurança**. Mudanças conflitantes exigem revisão humana e não são sobrescritas pelo script.

### Terminal A — aplicar no Arch Linux (sem `sudo`)

A partir da raiz exata do crate, **não** de `src/`:

```bash
cd ~/server/services/multiprotocol
pwd

test -f scripts/fase8_4_5_4c3_evidencias.py || exit 1
unzip -o ~/Downloads/fase8-4-5-4c4-classificacao-clientes-a-b-sem-corte-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .

python3 -B tests/test_fase8_4_5_4c4_classificacao.py
```

Esperado: `Ran 44 tests` e `OK` (número exato deste pacote).

**Primeiro, apenas leitura:**

```bash
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
python3 -B scripts/fase8_4_5_4c4_classificacao.py preflight --snapshot "$SNAPSHOT"
```

**Depois, criar apenas o novo cadastro lateral**, sem modificar C-v1:

```bash
python3 -B scripts/fase8_4_5_4c4_classificacao.py criar --snapshot "$SNAPSHOT"
```

**Revisar a matriz, somente leitura:**

```bash
python3 -B scripts/fase8_4_5_4c4_classificacao.py matriz --snapshot "$SNAPSHOT"
```

**Reavaliar C-v1 sem baixar pendências:**

```bash
python3 -B scripts/fase8_4_5_4c_prontidao_corte.py avaliar --snapshot "$SNAPSHOT"
```

**Atenção:** `avaliar` pode terminar com saída **3** (pendências), esperado. A C.4 deve manter a contagem real de C-v1 (21 no último log). `criar` é **exclusivo**, então não deve ser repetido após sucesso. Não executar `modelo` do registro C-v1.

### Somente quando houver evidências reais: declarações explícitas

**Não execute exemplos fictícios como se fossem evidência real.** Os comandos ilustram a interface, não são uma instrução para preencher o cadastro agora. Referências são identificadores curtos de inventário/relatório, não caminhos, URLs, credenciais ou texto de arquivos privados.

Exemplo genérico para um cliente REAL identificado, com referência real não secreta (substituir `<REFERENCIA_REAL_DA_EVIDENCIA>` pelo identificador do seu registro):

```bash
python3 -B scripts/fase8_4_5_4c4_classificacao.py registrar --snapshot "$SNAPSHOT" \
  --cenario A --identidade device-sensor02 \
  --estado declared-deployed --tipo-evidencia device-config \
  --referencia "<REFERENCIA_REAL_DA_EVIDENCIA>"
```

A situação `declared-not-deployed` só deve ser usada após confirmar que a conta não está implantada; ela **não exclui automaticamente a conta da política operacional, nem encerra os critérios C-v1**. Referências de evidências são privativas e não aparecem na saída do programa.

Propor política de Client IDs para `lab` no **cenário A** (exemplo de fluxo após discussão técnica, **sem aprovação de Segurança**):

```bash
python3 -B scripts/fase8_4_5_4c4_classificacao.py propor-politica-lab \
  --snapshot "$SNAPSHOT" --politica fixed-per-instance-proposed
```

A alternativa é `--politica dynamic-cli-proposed`. O registro de uma proposta não altera configuração do broker nem resolve a necessidade de aprovação formal. O laboratório B continua `dynamic-cli` independentemente de propostas para A.

### Segurança e integridade

- Operações `preflight` e `matriz`: somente leitura. `criar`: escreve **apenas** `classificacao-clientes-c4.json` se ainda não existir. `registrar` e `propor-politica-lab`: reescrevem atomicamente **apenas esse arquivo**, após verificar owner/permissões, hash e estabilidade do conteúdo.
- `~/.config/rust-server/phase8-4-5-4c/cadastro-prontidao.json` permanece intocado. As validações C-v1 são reutilizadas, com a evidência estática da bridge da C.3 necessária antes da criação C.4.
- Não imprimir nem armazenar senhas, tokens, chaves, TLS material, IDs de sensores inventados ou arquivos secretos. A referência aceita um formato restrito e não é impressa em `matriz`. Ainda assim, cabe ao operador não inserir valores sensíveis como referência.
- Não iniciar/encerrar Mosquitto em `8883`, `8884`, `8895` ou `8896`; não executar clientes MQTT, compilar o Rust, mudar ACL, fazer Git add/commit/push, acessar CI remoto, atualizar credenciais ou criar snapshot.
- Para autorizar uma migração real, ainda serão necessários clientes operacionais reais, plano de rotação e rollback do lado cliente, captura final e verificação de snapshot sob janela, monitoramento e aprovação de Segurança, Git/CI e responsáveis. Nada disso é afirmado como concluído pela C.4.

### Semântica dos retornos

- `0`: a ação de classificação solicitada foi executada com validações locais, **sem autorização de corte**;
- `2`: bloqueio de estrutura, fonte, branch, permissões, snapshot ou evidência conflitante;
- O script **não retorna `3`** para as 21 pendências C-v1; apresenta a contagem, mas a auditoria C-v1 original continua responsável pelo código 3 de pendências.

### Resultado esperado

Fase C.4 fica **tecnicamente aplicada** após testes e criação/leitura local do JSON privado; `lab` no cenário A permanece pendente de política, `bridge` e `device-sensor02` permanecem sem prova operacional, e a migração 8.4.5.5 para `8883` continua **NÃO AUTORIZADA**.
