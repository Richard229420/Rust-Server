> **ERRATA DE SEGURANCA — 10/11/2026:** A versao inicial C.8 validava somente o hash
> do arquivo C.7 e nao comparava a origem operacional com o snapshot historico.
> Esta versao reprova `iniciar`, `verificar`, `registrar` e `status` enquanto a auditoria
> real C.7 reprovar a linha de base. No Arch, a verificacao C.7/C.6 falhou com
> `snapshot desatualizado: origem diverge; reavaliar 8.4.5.2`, apos mudancas TLS.
> O indice C.8 existente deve ser PRESERVADO; nao apagar, reemitir snapshot com mesmo
> nome nem restaurar certificados antigos para enganar a validacao. A correcao e
> conservadora; a integracao com C.7 real precisa ser testada no Arch.

# Rust-Server — Fase 8.4.5.4-C.8: evidências das 21 pendências C-V1 (cenário A)

**Status inicial:** IMPLEMENTAÇÃO DA COLETA; **NÃO** é aprovação de prontidão operacional.

**Branch de referência:** `feature/fase8-4-inventory-dynsec`. **Linha de base:** C-V1 da fase 8.4.5.4-C, dossiê C.7 passivo e índice privado C.6. **Snapshot histórico:** `snapshot-20261029T165042Z-1aa693fc4484`.

A C.7 documentou **21 pendências**: 6 `lab`, 3 `bridge`, 6 `device-sensor02`, 6 operacionais. Sua coleta foi **passiva**, não houve prova suficiente dos clientes reais do cenário A e nenhuma baixa automática foi permitida. A B (laboratório) continua separada da A (operação principal). O broker principal **8883 não pode ser cortado**; não alterar credenciais, ACL, DynSec, serviço nem revogar/reabilitar contas por causa da C.8.

## Objetivo da C.8

Implementar um **índice independente de evidências redigidas**, uma checklist fiel às 21 linhas originais e um procedimento de encaminhamento à revisão externa. Os registros contêm somente identificadores opacos `EV-A-...`, SHA-256 de **documentos previamente redigidos**, tipo documental, item vinculado e timestamp. Não contêm arquivos reais, senhas, client IDs, hostnames, tokens, caminhos de evidência ou conteúdo de documentos. O arquivo privado C.8 fica fora do Git, em `~/.config/rust-server/phase8-4-5-4c/evidencias-cv1-c8.json` (0600; diretório 0700).

`registrar` **não** verifica autenticidade documental; o digest não garante autoria nem conformidade. Cada registro permanece `pending-independent-review`. O comando `status` sempre informa **21 pendências originais sem baixa**, porque aprovação de Segurança, Git/CI e operação não pode ser presumida pelo coletor. Não há comando para autorizar o corte.

## Matriz das 21 pendências originais

| ID C.8 | Grupo | Pendência C-V1 |
|---|---|---|
| LAB-01 | lab | Client ID real não registrado |
| LAB-02 | lab | Origem do Client ID não registrada |
| LAB-03 | lab | Evidência verificável pendente |
| LAB-04 | lab | `client_id_confirmado` pendente |
| LAB-05 | lab | `cliente_suporta_troca_credencial` pendente |
| LAB-06 | lab | `retorno_credencial_legada_planejado` pendente |
| BRI-01 | bridge | `client_id_confirmado` pendente |
| BRI-02 | bridge | `cliente_suporta_troca_credencial` pendente |
| BRI-03 | bridge | `retorno_credencial_legada_planejado` pendente |
| SNS-01 | device-sensor02 | Client ID real não registrado |
| SNS-02 | device-sensor02 | Origem do Client ID não registrada |
| SNS-03 | device-sensor02 | Evidência verificável pendente |
| SNS-04 | device-sensor02 | `client_id_confirmado` pendente |
| SNS-05 | device-sensor02 | `cliente_suporta_troca_credencial` pendente |
| SNS-06 | device-sensor02 | `retorno_credencial_legada_planejado` pendente |
| OPS-01 | operacionais | `canal_distribuicao_secreta_definido` pendente |
| OPS-02 | operacionais | `procedimento_rotacao_documentado` pendente |
| OPS-03 | operacionais | `reconfiguracao_cliente_testada_fora_de_producao` pendente |
| OPS-04 | operacionais | `rollback_reconexao_testado_fora_de_producao` pendente |
| OPS-05 | operacionais | `janela_e_responsaveis_definidos` pendente |
| OPS-06 | operacionais | `monitoramento_e_criterios_aborto_definidos` pendente |

### Roteiro mínimo por grupo

**LAB (6):** descobrir quem realmente usa CLI no cenário A, quantas instâncias existem, origem dos Client IDs e contas e se há conta CLI compartilhada. Não preencher um ID inventado para satisfazer um schema pensado para IDs fixos: qualquer mudança de política/schema depende de revisão de Desenvolvimento e Segurança. Documentar credenciais e retorno de cada instância por referência opaca, sem seus valores.

**BRIDGE (3):** a string `rust-server-bridge-local` identificada no **código** não demonstra execução no cenário A. Requer relato redigido de processo/serviço real, binário/versão, TLS, ID efetivo e teste isolado de troca/retorno das credenciais. Não capturar `cmdline`, `environ` nem arquivos `.opts` completos.

**SENSOR02 (6):** identificar host/dispositivo, versão de firmware/cliente e ID efetivo por inventário **autorizado**; ensaio de atualização e reconexão fora de produção. Se não implantado, comprovar a não implantação e solicitar **exclusão formal do escopo**; não marcar automaticamente como resolvido.

**OPERACIONAIS (6):** responsabilidades e custódia dos segredos, canal autenticado, runbook de rotação, ensaios de reconfiguração e rollback por cliente real, janela de mudança, comunicação, métricas/alertas e critérios de aborto. Captura de snapshot final **somente** sob janela aprovada; backup de laboratório 8884 não substitui o snapshot operacional final.

## Uso no Arch Linux

Partindo de `~/server/services/multiprotocol`, com scripts C.6 e C.7 já existentes:

```bash
cd ~/server/services/multiprotocol
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
C8="scripts/fase8_4_5_4c8_evidencias_cv1.py"

# Revisar a linha de base existente, sem qualquer escrita
python3 -B scripts/fase8_4_5_4c7_coleta_evidencias.py verificar --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_4c6_inventario_operacional.py avaliar --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_4c_prontidao_corte.py avaliar --snapshot "$SNAPSHOT"

# Criar indice privado C.8 UMA VEZ (nao sobrescreve arquivo existente)
python3 -B "$C8" iniciar --snapshot "$SNAPSHOT"

# Conferir as 21 linhas, sem expor referencias
python3 -B "$C8" roteiro
python3 -B "$C8" verificar
python3 -B "$C8" status
```

`iniciar` confere se o C.7 local privado está presente com modo 0600 e grava o digest da fonte. Se já existir um índice C.8, use `verificar` e `status`; **não o apague para recomeçar**. Mudanças posteriores no dossiê C.7 exigem revisão do vínculo de baseline; o C.8 bloqueia automaticamente, sem rebase silencioso.

### Registrar uma evidência real, somente depois de coletada e redigida

Crie o **documento redigido** fora do Git, em repositório privado adequado; faça a revisão para remover senhas, tokens, Client IDs reais e identificadores sensíveis. O documento precisa representar o **cenário A**, com origem/verificação autorizadas e apoio do responsável. Registre primeiro a referência no índice C.6 conforme a interface **já existente** (não foi modificada pelo C.8). Depois vincule essa referência opaca ao item C.8:

```bash
# Exemplo: substitua pelos metadados reais de documento ja redigido.
# NUNCA passe senha, caminho privado ou Client ID em --referencia.
C8="scripts/fase8_4_5_4c8_evidencias_cv1.py"
python3 -B "$C8" registrar \
  --item BRI-01 \
  --referencia EV-A-EXEMPLO1234 \
  --sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --tipo inventario-redigido

python3 -B "$C8" verificar
python3 -B "$C8" status
```

**Atenção:** a linha acima é exclusivamente **modelo de sintaxe**, não evidencia o item. Não a execute com os valores de exemplo. Para calcular o hash do documento já redigido: `sha256sum -- "$ARQUIVO_REDIGIDO"` — o arquivo e seu conteúdo não são incorporados à C.8. O mesmo documento pode fundamentar mais de um item, sempre com o **mesmo** digest. Referências opacas devem ser identificáveis por custodiante em registro externo de acesso controlado.

### Encaminhamento para revisão independente

1. Analisar o documento redigido, sua fonte, momento e vínculo ao cliente **real** no cenário A. Confirmar autenticidade e integridade via o custodiante, não apenas pelo SHA-256.
2. Comparar a prova e seu item C-V1, a associação no C.6 e a arquitetura C-v2; para `lab`, deliberar explicitamente o risco da conta CLI/IDs dinâmicos.
3. Obter deliberação independente de Segurança, Git/CI, operação e responsáveis pela janela; registrar resultado fora do C.8.
4. Somente o processo de governança previamente acordado pode alterar o cadastro C-V1 e revisar prontidão. **C.8 não altera nem baixa o cadastro**, mesmo com 21 evidências registradas.

## Restrições e regressões

- Nenhum acesso MQTT, rede, subprocesso, broker, DynSec, segredo, `password_file`, cert/key, Git push, `systemd` ou operação de corte.
- Nenhuma conexão de `device-sensor01` revogado.
- A/B separados; C.8 só permite referências do cenário A.
- Modo 0600, diretório 0700, sem links simbólicos nem hardlinks para o índice, lock para escrita e gravação atômica.
- Não guardar o índice C.8 nem os documentos privados sob `~/server`.
- O escopo 8884 PKI v2 está encerrado separadamente; **isso não é prova para as 21 pendências operacionais A**.
- Retorno do comando `verificar`: confirma integridade **estrutural** e vínculo com C.7; não valida a credibilidade das provas.

## Testes

```bash
cd ~/server/services/multiprotocol
python3 -B tests/test_fase8_4_5_4c8_evidencias_cv1.py
python3 -B scripts/fase8_4_5_4c8_evidencias_cv1.py roteiro
```

**Critério de aceite desta implementação:** 21 testes isolados aprovados, roteiro 21/21, índice privado criado (sem sobrescrever C.6/C.7), saída reportando 21 bloqueios e nenhuma operação de broker. **Não equivale a aprovar o cenário A ou o corte 8883.**

## Diagnostico de divergencia pos-renovacao

Em 10/11/2026 a linha de base C.7/C.6 apontou divergencia entre os arquivos
atuais e o snapshot original de 29/10/2026. A C.8 foi inicializada antes da
verificacao cruzada ser implementada. Seu indice privado 0600 e preservado,
mas **nao esta apto a aceitar novas evidencias** ate reconciliacao da linha
de base e das dependencias C-v1, C-v2, C.6 e C.7, em revisao especifica.

Diagnostico sem alteracoes: utilizar `python3 -B scripts/fase8_4_5_4c7_coleta_evidencias.py verificar --snapshot "$SNAPSHOT"`,
`python3 -B scripts/fase8_4_5_4c6_inventario_operacional.py avaliar --snapshot "$SNAPSHOT"`
e examinar `scripts/fase8_4_5_3_ensaio.py` nas linhas da verificacao
`assert_origins_match` para identificar os arquivos comparados, sem imprimir
segredos nem dar baixa. **Nao** executar `coletar`, `criar` ou `preparar` antes
de decidir o plano de migracao da linha de base.
