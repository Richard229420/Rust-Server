# Rust-Server — Fase 8.4.5.5-A: preparação controlada, sem corte

## Objetivo

Preparar, **sem executar**, a eventual migração do broker legado em `127.0.0.1:8883` para Mosquitto Dynamic Security. Cenário **A é operacional principal**; cenário **B é laboratório/homologação**. Esta etapa é **NO-GO por construção** e nunca executa a 8.4.5.5-B. Sem operação MQTT, sem mudança de configuração, sem reinício, sem rotação produtiva, sem Git de escrita.

### Estado de partida fundamentado

- C.1 (bridge Rust) e C.2 (clientes MQTT) aprovadas **somente em laboratório**.
- C.3 registrou o Client ID **estático** `rust-server-bridge-local` da fonte Rust, **sem confirmação do processo operacional**.
- C.4 classifica A/B; `lab` em A aguarda revisão da política de IDs, `device-sensor02` tem implantação desconhecida.
- C.6 guarda índice privado separado, C.7 uma coleta **histórica/passiva**. Na última saída compartilhada, C.6 tinha **zero referências por identidade**.
- Cadastro C-v1 permanecia com **21 pendências**: `lab=6`, `bridge=3`, `device-sensor02=6`, `operacionais=6`.
- `device-sensor01` continua **revogado**. Os brokers `8883`/`8884` **não devem ser modificados**, e os ensaios isolados não autorizam o corte real.
- A aprovação de CI que foi relatada na conversa de Git/CI e um PR aberto **não equivalem à aprovação de Segurança nem à decisão operacional GO**. Esta fase não consulta GitHub.
- Snapshot antigo de 8.4.5.2: `~/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484`, contendo vinte arquivos verificados. Preservar; **não confundir com backup final da janela**.

## Implementação

Arquivo novo: `scripts/fase8_4_5_5a_preparacao.py`. Aceita quatro ações:

| Ação | Operação | Grava arquivos? |
|---|---|---|
| `preflight` | Valida com as APIs existentes os pré-requisitos C-v1/C-v2/C.6/C.7, o snapshot e a branch; observa passivamente listeners TCP | Não |
| `plano` | Mostra a sequência de trabalho futuro e controles de bloqueio | Não |
| `criar` | Cria **uma única vez** o JSON privado de preparação, exclusivo, `0600` | **Sim, só arquivo novo** |
| `avaliar` | Revalida JSON, vínculos de snapshot/C.7 e checklist; sempre **NO-GO** | Não |

Arquivo privado criado somente por `criar`:

```
~/.config/rust-server/phase8-4-5-4c/preparacao-corte-8455a.json
```

O JSON inclui vínculos SHA-256 do manifesto do snapshot e da coleta C.7; **não inclui** segredos, caminhos de evidências, comandos operacionais, Client IDs privados, resultados de autenticação, hashes de senha ou assinaturas de autorização. Seu campo `cutover_authorized` permanece `false`, `decision` permanece `NO-GO`; todas as 14 exigências e três revisões ficam pendentes e não são alteráveis por esta fase. O registro rejeita edições de status ou simulação de aprovações. Não editar manualmente para `GO`.

### Limites de verificação

- A consulta a `/proc/net/tcp` e `/proc/net/tcp6` lê **apenas listeners TCP** nas portas `8883`, `8884`, `8895` e `8896`; não abre sockets, não interrompe processos, não expõe endereços. Estado de leitura indisponível **não é interpretado como porta fechada**. A consulta não identifica qual serviço está ligado nem atesta conectividade MQTT/TLS.
- O preflight usa a leitura e validação do snapshot legado; seus hashes são conferidos localmente, sem imprimir os vinte arquivos privados.
- A coleta C.7 é um registro de observações do passado; sua integridade não prova implantação atual.
- Se o número de pendências mudar (não forem as 21 conhecidas), o script **bloqueia** para revisão manual. Esse bloqueio é temporário e intencional para a continuidade desta versão de planejamento.
- Revisão Git/CI, Segurança e prontidão são decisões **externas**. Não há gatilho de liberação automática.

## Ordem segura no Arch Linux — Terminal A

**Importante:** executar como usuário normal, **sem `sudo`**, na **raiz de `services/multiprotocol`**, não em `src/`.

```bash
cd ~/server/services/multiprotocol
pwd
unzip -o \
  ~/Downloads/fase8-4-5-5a-preparacao-controlada-sem-corte-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .

python3 -B tests/test_fase8_4_5_5a_preparacao.py
```

Esperado: `Ran 47 tests` seguido de `OK`.

```bash
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"

python3 -B scripts/fase8_4_5_5a_preparacao.py preflight --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_5a_preparacao.py plano --snapshot "$SNAPSHOT"
```

Se o preflight for aprovado, criar o plano **uma única vez**, sem sobrescrever:

```bash
A5="$HOME/.config/rust-server/phase8-4-5-4c/preparacao-corte-8455a.json"
if test -e "$A5" || test -L "$A5"; then
    echo "Plano 8.4.5.5-A ja existe: preservar"
else
    python3 -B scripts/fase8_4_5_5a_preparacao.py criar --snapshot "$SNAPSHOT"
fi

python3 -B scripts/fase8_4_5_5a_preparacao.py avaliar --snapshot "$SNAPSHOT"
```

**`avaliar` retorna código de saída `3` enquanto as pendências persistirem — esperado e NÃO AUTORIZAÇÃO.** Código `2` é erro/bloqueio: não dar prosseguimento sem diagnóstico. `preflight`, `plano` e `criar` retornam `0` quando executados corretamente, mas isso **não significa autorização** de corte.

### Matriz de requisitos preparatórios (14)

| Grupo | Evidência ou decisão exigida antes da etapa 8.4.5.5-B |
|---|---|
| Identidade | 1. Bridge real identificada e verificada |
| Identidade | 2. `lab`: escopo e política de Client ID validados por Segurança |
| Identidade | 3. `device-sensor02`: implantação ou não implantação/exclusão documentada |
| Segurança | 4. ACL produtiva revisada, `device-sensor01` revogado |
| Segredos | 5. Canal autenticado, cofre, custódia e autorização definidos |
| Segredos | 6. Plano de rotação e retorno das credenciais documentado e homologado |
| Clientes | 7. Reconfiguração dos clientes reais ensaiada em homologação isolada |
| Clientes | 8. Reconexão de rollback ensaiada para cada cliente real |
| Broker | 9. Recuperação do broker e reconexão de todos os clientes planejadas |
| Monitoramento | 10. Observabilidade mínima, alertas e gatilhos para abortar definidos |
| Operação | 11. Janela, responsáveis, comunicação e plano de retorno definidos |
| Backup | 12. Captura final na **futura** janela prevista (não executar agora) |
| Aprovação | 13. Decisão formal e independente de Segurança |
| Aprovação | 14. Revisão Git/CI formal e vigente, com estado do PR/commit |

**Além destes 14 requisitos**, a operação precisa de responsável pela decisão de GO/NO-GO na janela, autorização operacional e verificação de estado final. Nada disso é suprido pela presença de um documento JSON, de um hash ou de uma suíte de testes unitários.

### Sequência operacional FUTURA (não executável nesta fase)

1. Revisar inventário e escopo A, excluir formalmente identidades não implantadas; confirmar ACL mínima e revogação do `sensor01`.
2. Submeter evidências redigidas à Segurança e ao chat Git/CI; receber decisões explícitas. A PKI v2 ensaiada em laboratório não é prova de compatibilidade final de todos os clientes A.
3. Homologar credenciais novas **não recicladas do laboratório** e retorno seguro por cliente real, em ambiente isolado. Não revelar credenciais no chat/CI/repositório.
4. Definir responsáveis, contatos, tempo máximo de indisponibilidade, métricas e limites objetivos de aborto, sem inventar números não aprovados.
5. Formalizar janela; sob autorização explícita, capturar e verificar snapshot **final** do estado atual antes de qualquer alteração. Preservar credenciais legadas somente enquanto durar a janela de reversão e sob custódia restrita.
6. Nova decisão GO/NO-GO com todas as aprovações e evidências. Se qualquer item falhar, **NO-GO**: não iniciar 8.4.5.5-B.
7. Somente a futura fase 8.4.5.5-B, autorizada separadamente, poderá executar a migração. A 8.4.5.6 deverá validar TLS, ACL, clientes, monitoração e recuperação após esse evento.

### Critérios de aborto a definir antes da janela (sem valores inventados)

- Cliente real indispensável sem autenticação/reconexão ou sem rollback comprovado.
- Falha na confiança TLS/CA, divergência de certificados/hostname, ACL negando tráfego legítimo ou permitindo tráfego revogado.
- Perda de capacidade de restaurar broker e clientes, divergência de hashes ou snapshot final inválido.
- Monitoramento indisponível ou ausência de responsáveis e canais de comunicação.
- Qualquer autorização externa ausente, revogada ou desatualizada.

## Testes e escopo da aprovação

`tests/test_fase8_4_5_5a_preparacao.py` testa 47 situações offline: campos fixos e modelo `NO-GO`, rejeição de aprovações forjadas, vínculos de snapshot/C.7, permissões `0600/0700`, symlink/hardlink, escrita exclusiva, parsing passivo TCP/IPv4/IPv6, estados desconhecidos e códigos de saída de preflight, plano, criar e avaliar.

Os testes **não** substituem execução no Arch com os cadastros e snapshot reais. C.7 deve estar previamente instalada e aprovada, e o pacote A **não** substitui suas dependências.

**Não executar** `mosquitto`, `mosquitto_ctrl`, comandos de escrita do Git, reinícios de serviços, rotação real, restauração de snapshot ou alteração na porta `8883` nesta fase.
