# Rust-Server — Fase 8.4.5.4-C.6

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

## Inventário passivo e indexação privada de evidências — SEM CORTE

**Escopo:** Cenário A (operacional principal). O Cenário B permanece exclusivamente para testes e homologação. A entrega não comprova clientes remotos, não conecta a MQTT, não inicia/encerra Mosquitto, não modifica credenciais ou ACLs, não escreve no cadastro C-v1/C-v2 e **não autoriza migração do broker para 127.0.0.1:8883**.

### Entradas e interfaces preservadas

- Branch exigida: `feature/fase8-4-inventory-dynsec`.
- Snapshot privado existente da Fase 8.4.5.2: `~/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484`.
- C-v1: `~/.config/rust-server/phase8-4-5-4c/cadastro-prontidao.json` — **não modificar** com C.6.
- C-v2: `~/.config/rust-server/phase8-4-5-4c/classificacao-clientes-c4.json` — **não modificar** com C.6.
- C.3: fonte estática revisada da bridge `rust-server-bridge-local`, usuário `bridge`.
- C.5: funções de validação de snapshot, fontes, branch, cadastros e gates.
- Novo índice C.6: `~/.config/rust-server/phase8-4-5-4c/evidencias-operacionais-c6.json`, arquivo **0600**, pasta privada **0700**, somente no host, fora do Git.

O novo índice vincula referências (identidade, tipo e SHA-256 de **artefato previamente redigido**) ao fingerprint do snapshot original. Um hash não atesta que o arquivo foi revisado, que a origem é confiável ou que a conexão MQTT ocorreu. Nenhuma aprovação é gravada. O índice não importa, lê, copia ou armazena evidências originais.

### Instalação (Terminal A, não executar em `src/`)

```bash
cd ~/server/services/multiprotocol

unzip -o \
  ~/Downloads/fase8-4-5-4c6-inventario-evidencias-operacionais-sem-corte-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' \
  -d .

python3 -B tests/test_fase8_4_5_4c6_inventario_operacional.py
```

Esperado: `Ran 55 tests` e `OK`.

### Execução: somente leitura primeiro

```bash
cd ~/server/services/multiprotocol
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"

python3 -B scripts/fase8_4_5_4c6_inventario_operacional.py \
  preflight --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_4c6_inventario_operacional.py \
  inventariar --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_4c6_inventario_operacional.py \
  plano --snapshot "$SNAPSHOT"
```

`inventariar` verifica somente os **nomes** de quatro variáveis de ambiente no `scripts/env_phase8.sh` (não mostra valores), a fonte Rust já validada pelo preflight e apenas `/proc/PID/comm` para possíveis nomes de processos locais. Não consulta `/proc/PID/environ` nem `/proc/PID/cmdline`. Não procura dispositivos remotos. A ausência de processos não prova que clientes nunca foram implantados.

### Criar índice privado (uma vez; é a única gravação inicial da C.6)

O comando abaixo não sobrescreve arquivo existente:

```bash
C6="$HOME/.config/rust-server/phase8-4-5-4c/evidencias-operacionais-c6.json"
if test -e "$C6" || test -L "$C6"; then
  echo 'Indice C.6 existente: preservado'
else
  python3 -B scripts/fase8_4_5_4c6_inventario_operacional.py \
    criar --snapshot "$SNAPSHOT"
fi

python3 -B scripts/fase8_4_5_4c6_inventario_operacional.py \
  avaliar --snapshot "$SNAPSHOT"
```

O índice começa vazio e considera `lab`, `bridge` e `device-sensor02` como **não comprovados**. `device-sensor01` permanece revogado/excluído. Os **21 itens do C-v1** seguem pendentes se o cadastro não mudou.

### Indexar evidências posteriormente (opcional)

Este passo **não deve ser executado antes de existir um relatório REAL já redigido**, guardado em local privado e inspecionado pelo operador. Nunca use no `--sha256` hash de um arquivo que contenha senhas, segredos ou dados pessoais; não forneça os arquivos originais como argumentos deste comando. Exemplo de fluxo com variáveis, a adaptar apenas com evidência real:

```bash
# Exemplo ilustrativo; NAO executar com dados ficticios.
# RELATORIO_REDIGIDO deve existir num local privado fora do repositorio Git.
# REFERENCIA deve ser um identificador opaco, sem segredo ou caminho.
# hash calculado localmente, sem importar o arquivo para o indice:
# HASH_REDIGIDO="$(sha256sum "$RELATORIO_REDIGIDO" | awk '{print $1}')"
# python3 -B scripts/fase8_4_5_4c6_inventario_operacional.py registrar \
#   --snapshot "$SNAPSHOT" \
#   --identidade bridge \
#   --tipo runtime-redacted \
#   --referencia "$REFERENCIA" \
#   --sha256 "$HASH_REDIGIDO"
```

Tipos permitidos: `runtime-redacted`, `configuration-redacted`, `client-change-lab`, `rollback-lab`, `not-deployed-inventory`, `operator-scope`. Referências devem ser curtas, opacas e sem `password`, `token`, `secret`, caminhos, URLs ou conteúdo de credenciais. São imutáveis por identidade: divergências não são sobrescritas; reexecutar a mesma referência é idempotente. O índice **nunca** marca uma evidência como aprovada, não reduz as pendências C-v1 e não promove teste B a prova de A.

### Evidências exigidas por identidade

| Identidade | Cenário A — evidência real exigida | Cenário B — o que já foi ensaiado |
|---|---|---|
| `bridge` | Host/processo ou unidade real, versão, destino TLS, Client ID efetivo, teste de troca e retorno | Bridge Rust local em broker isolado; C.1 aprovada |
| `lab` | Relação de operadores/instâncias reais, política de IDs dedicada ou revisão formal de segurança, mínimo privilégio, troca/retorno por cliente | CLI com IDs dinâmicos e ACLs; C.2 aprovada |
| `device-sensor02` | Dispositivo/serviço e configuração efetivos; firmware, ID, troca/retorno; ou prova de não implantação e decisão formal de escopo | Cliente simulado; C.2 aprovada |

Evidências operacionais externas são necessárias ainda que os arquivos locais estejam corretos. Se não houver implantação do sensor02, é possível documentar ausência e decidir a exclusão formal do corte; a C.6 **não** declara exclusão automaticamente.

### Impedimentos de migração que continuam em vigor

- 21 pendências declarativas C-v1 no estado confirmado após C.3/C.4/C.5.
- Aprovação independente de Segurança e Git/CI não está contida neste índice.
- Canal seguro para credenciais, rotação, testes de reconexão e rollback de **clientes reais**, responsáveis/janela/monitoramento/abortos e **snapshot final de manutenção** continuam exigidos.
- Migração para `8883` e rollback real continuam não autorizados. Broker original `8883`, laboratório `8884`, ensaio `8895/8896`, credenciais e ACLs não devem ser alterados por esta etapa.

### Diagnóstico

- Saída `BLOQUEIO`: verificar branch, integridade do snapshot, C.3, C.4 e C.5, arquivo novo e permissões. Não corrigir alterando fontes pinadas ou forçando flags.
- Arquivo inexistente ao executar `avaliar`: executar `criar` **somente se ainda não existir**.
- Registro divergente: consultar o índice privado local e encaminhar revisão, nunca remover/editar automaticamente.
- Com `--snapshot`, usar o diretório do snapshot **existente**, não criar outro na C.6.
