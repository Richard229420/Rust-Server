# Rust-Server — Termo de encerramento técnico da renovação TLS (Fase 8.4 / laboratório MQTT 8884)

**Identificador:** RS-F8.4-MQTT-8884-TLS-V2-ENC-20261110\
**Emissão:** 10/11/2026 (America/Sao_Paulo)\
**Status:** **ENCERRADO TECNICAMENTE — escopo restrito à renovação TLS do laboratório 8884**\
**Repositório:** `~/server` · Serviço: `services/multiprotocol`\
**Branch observada nas evidências:** `feature/fase8-4-inventory-dynsec` · Versão observada: `v0.2.2`\
**Base das conclusões:** saídas de comandos e ensaios fornecidas pelo operador; nenhum acesso remoto ou alteração direta na máquina foi realizado durante a elaboração deste termo.

> **Delimitação fundamental:** o encerramento deste documento **não** aprova o cenário operacional A, **não** reduz as 21 pendências C-V1 e **não** autoriza iniciar, alterar ou migrar o broker principal `8883`.

## 1. Objeto, limites e decisão

**Objeto encerrado:** renovação do material de confiança TLS do Mosquitto 2.1.2 usado pelo laboratório Dynamic Security em `127.0.0.1:8884`, com validação de compatibilidade de dois clientes habilitados, testes de autorização em ambiente isolado e adoção de uma única instância supervisionada por `systemd --user`.

**Decisão:** **APROVADO PARA ENCERRAMENTO TÉCNICO** da renovação TLS do laboratório `8884`, com controles de continuidade descritos na seção 6. A homologação de clientes/dispositivos reais do cenário A e o rollback operacional pós-implantação não fazem parte da aprovação.

**Exclusões expressas:** `8883`; migração de tráfego/credenciais do broker principal; implantação em dispositivos externos; alteração de usuários, senhas ou ACLs do cenário A; autorizações organizacionais, PR/merge/tag Git e declaração de conformidade geral da Fase 8.4.

## 2. Linha de base criptográfica e recuperação

| Item | Evidência consolidada | Parecer |
|---|---|---|
| PKI v2 | CA `Rust-Server MQTT Lab CA v2`, válida até **07/11/2028**; certificado `CN=localhost` válido até **07/05/2027**, com SAN de `localhost` e `127.0.0.1` | Validada previamente com verificação X.509 estrita e correspondência de hostname/IP |
| CA anterior | Certificado antigo do servidor válido até **26/11/2026**; CA antiga até **27/11/2026** | Retorno temporário viável apenas dentro da validade e mediante testes |
| Bundle de transição | `trust-bundle-old-v2.crt`, contendo as duas CAs públicas; arquivo privado do staging com permissão `0600` | Verificou ambos os certificados de servidor; uso transitório |
| Backup de recuperação | `~/server_backups/renovacao_mqtt_v2/pre-8884-tls-v2-zRBVeD80.tar.gz.nova-senha.gpg` | Cópia GPG com nova senha e recuperação conferida em isolamento |
| Conteúdo restaurado | Recuperação isolada dos **13 arquivos** com comparação byte a byte; SHA-256 do TAR original recuperado `cf7ed01368871af88034b7bf42ee5b1e3e1745aa06a071c185ff673123c6b34b` | Aprovada **para recuperação de arquivos**, não homologação de rollback vivo |
| DynSec | Banco `dynamic-security.json` preservado durante implantação e ensaios; `device-sensor01` manteve `disabled: true` | Revogação preservada em cadastro; não houve login do sensor01 |

**Proteção de dados:** arquivos `.opts`, `dynamic-security.json`, chaves privadas, senhas, hashes de autenticação e a frase-senha GPG **não** integram este documento e devem permanecer fora do Git. A existência anterior de TAR em claro e de cópia GPG com frase-senha potencialmente exposta requer avaliação e descarte controlado; exclusão lógica em SSD não garante apagamento físico.

## 3. Cadeia de validação técnica

| Fase / evidência | Resultado observado | Limite |
|---|---|---|
| PKI v2 e TLS de ensaio (8897) | Handshake e publicação/assinatura aprovados | Broker descartável |
| Dynamic Security 8898–8899 | Autenticação e 6/6 controles de permissão/rotação/revogação aprovados | Base de ensaio; não equivale ao cenário A |
| Candidato `8900` | TLS com CA v2 e bundle aceitos; anônimos rejeitados | Broker temporário |
| Candidato `8900`, autenticação | `device-sensor02` e `lab84-bridge`: `CONNACK 0` | Contas de laboratório, não operadores externos |
| Candidato `8900`, ACLs | **5/5 etapas**: entrega autorizada do sensor02 à bridge, publicações proibidas bloqueadas, assinaturas proibidas com `SUBACK 135`, integridade de bases e listener liberado | ACLs testadas na cópia temporária |
| Recuperação isolada `8901` | Certificado/CA antigos verificados; ambas as identidades autenticaram; bancos preservados; porta liberada | **Não** houve rollback real após a implantação no 8884 |
| Controlador Python | SHA-256 `c279f3ed1cc5bae3a705627acb282d3653ac631187598da6442646943e718754`; **4/4 testes unitários aprovados no Arch** | Fixtures exercitam lógica e bloqueios, não todo o Mosquitto |
| `preflight` + `prepare` | Aprovados; plano privado criado em `~/.config/rust-server/renovacao-mqtt-staging/implantacao-8884-pki-v2`; estado `prepared` | Sem alteração nos arquivos ativos nessa etapa |
| `deploy` no 8884 | **APROVADO**: PKI v2 e confiança dos clientes habilitados atualizadas offline; banco DynSec, configuração e `.opts` do sensor01 preservados | Troca realizada com 8884 parado |
| `validate` no 8884 | **APROVADO**: TLS e autenticação de `device-sensor02` e `lab84-bridge`; estado `validated-offline`; listener liberado ao final | Teste controlado, não operação contínua |
| Repetição de `deploy` | **BLOQUEADA**, pois o plano já não estava em `prepared` | Bloqueio preventivo correto |
| TLS em operação | `TLSv1.3`, `TLS_AES_256_GCM_SHA384`, certificado `CN=localhost`, `Verification: OK`, hostname `localhost` validado e grupo `X25519MLKEM768` | Handshake não demonstra sozinho autorização MQTT |

Os testes originais foram conduzidos no Arch Linux do operador; esta consolidação foi feita a partir das saídas fornecidas na conversa. Nenhum hash de certificado emitido em tempo real foi fornecido para incorporar como evidência de fingerprint, portanto não é inventado aqui.

## 4. Operação contínua e incidente resolvido

Houve inicialmente **concorrência entre o Mosquitto manual (`serve`) e a unidade systemd**, causando `Address already in use`, reinícios e `start-limit-hit`. A instância manual foi encerrada com `Ctrl+C`, o estado de falha da unidade foi limpo e a unidade passou a controlar sozinha o listener. **O incidente pertence à inicialização, não à validade da PKI v2.**

**Última amostra operacional recebida — 10/11/2026:**

```text
ActiveState=active
SubState=running
MainPID=961
NRestarts=0
ExecMainStartTimestamp=Tue 2026-11-10 13:56:15 -03
enabled
LISTEN ... 127.0.0.1:8884 ... users:(("mosquitto",pid=961,fd=5))
```

- O `MainPID` e o PID do listener **coincidem**; serviço ativo e escutando somente em loopback.
- A unidade `rust-server-mqtt-lab-8884.service` está **enabled** no `systemd --user`. Isso habilita início com o gerenciador de usuário; **não** comprova funcionamento antes do login nem após logout sem configuração específica.
- O `NRestarts=0` se refere à **ativação atual**. O início em 10/11 às 13:56:15 não comprova continuidade ininterrupta desde 09/11.
- A consulta anterior ao journal desde 09/11/2026 16:40:44 retornou `-- No entries --` no nível warning. Essa observação é limitada à janela e ao conteúdo consultados; não substitui monitoramento contínuo.
- Os antigos erros de `Address already in use` e `start-limit-hit` foram identificados e resolvidos mediante exclusividade de instância. Não executar `serve` em paralelo com a unidade.

**Veredito da operação:** aceitação inicial da supervisão systemd **APROVADA**; acompanhamento prolongado, observabilidade futura e validação de nova sessão permanecem controles de rotina, sem invalidar o encerramento técnico TLS.

## 5. Critérios de aceite e exceções

| Critério | Parecer |
|---|---|
| Certificado v2 instalado e verificado por cadeia TLS | **ATENDIDO** |
| Autenticação dos dois clientes habilitados no 8884 após a troca | **ATENDIDO** |
| ACLs positivas/negativas em cópia isolada de configuração | **ATENDIDO no laboratório isolado** |
| Conta `device-sensor01` mantida revogada no cadastro | **ATENDIDO** |
| Banco DynSec e configuração do broker não sobrescritos | **ATENDIDO no procedimento observado** |
| Backup criptografado recuperável e rollback antigo ensaiado em isolamento | **ATENDIDO com ressalva de ambiente** |
| Serviço 8884 ativo, exclusivo e supervisionado por systemd | **ATENDIDO na amostra operacional de 10/11** |
| Prova de continuidade 24×7 após logout/boot | **NÃO COMPROVADA / fora do aceite TLS** |
| Rollback real pós-implantação na porta 8884 | **NÃO EXECUTADO, por não haver falha que o justificasse** |
| Identidades e dispositivos reais do cenário A | **NÃO COMPROVADOS; 21 pendências C-V1 preservadas** |
| Operação ou migração do broker 8883 | **NÃO AUTORIZADA** |

## 6. Operação e recuperação após o encerramento

**Método único de operação:** unidade de usuário `rust-server-mqtt-lab-8884.service`. Evitar uso simultâneo de `python3 ... serve`. Para verificação **somente de leitura**:

```bash
UNIT='rust-server-mqtt-lab-8884.service'
systemctl --user show "$UNIT" -p ActiveState -p SubState -p MainPID -p NRestarts -p ExecMainStartTimestamp
systemctl --user is-enabled "$UNIT"
ss -lntp | rg ':8884\b'
journalctl --user -u "$UNIT" -p warning --since '2026-11-10 13:56:15' --no-pager
```

**Recuperação em caso de incidente:** registrar o motivo e a janela de intervenção; parar **somente** a unidade 8884 via `systemctl --user stop`; verificar porta livre; revisar integridade do manifesto e do backup GPG; somente então considerar `rollback --confirm RESTAURAR-TLS-8884` e `validate-rollback`, acompanhados por `status`. O controlador preserva o banco DynSec, a revogação e o 8883. **Não executar rollback preventivo** nem retornar ao certificado antigo após seu vencimento em 26/11/2026; nesse caso, emitir material TLS válido para recuperação. O rollback pós-corte **não foi exercitado no broker ativo**.

**Ciclo de vida:** planejar a retirada da CA antiga do bundle de confiança após a transição autorizada; revisar o certificado de servidor v2 antes de 07/05/2027; proteger e avaliar destino dos backups em claro/antigos; manter as permissões dos segredos fora do versionamento.

## 7. Pendências e responsabilidades preservadas

1. **21 pendências C-V1:** abertas, dependentes de evidências do cenário operacional A, operadores, dispositivos e gates independentes. Não considerar `lab`, `bridge` ou `device-sensor02` do ambiente de ensaio como comprovação dos clientes externos.
2. **8883:** nenhuma migração, mudança de configuração ou autorização de corte registrada.
3. **Recuperação pós-implantação:** plano disponível, ensaio com CA antiga feito na porta 8901; não houve restauração real após a troca. Não há necessidade técnica de provocar um incidente para homologar o encerramento TLS.
4. **Supervisão:** coletar periodicamente status/PID, reinícios e avisos; validar início automático após nova sessão conforme política local.
5. **Gestão Git/CI:** relatório público apenas com evidências saneadas; revisar diff e escopo antes de commit/PR. Este termo não registra merge, tag, aprovação organizacional ou alteração no Git.

## 8. Registro de decisão

**Objeto:** renovação TLS da Fase 8.4, laboratório `127.0.0.1:8884`.\
**Decisão técnica:** **ENCERRADO E APROVADO EM 10/11/2026**, com validação offline da PKI v2 e autenticação no 8884, ACLs validadas em laboratório isolado e serviço de usuário ativo na última evidência.\
**Condição residual:** monitoramento de rotina, ciclo de vida da CA de transição e controles documentados neste termo.\
**Não implica:** aceite do cenário A, redução das 21 pendências C-V1, corte do 8883, certificado de conformidade nem assinatura de aprovador externo.

**Responsável pela execução e aprovação organizacional (se exigido):** não informado; preenchimento posterior pelo responsável designado.\
**Fonte das evidências:** saídas de terminal fornecidas pelo operador durante a fase de homologação e implantação.\
**Local recomendado no repositório:** `~/server/docs/FASE8_4_RENOVACAO_MQTT_TLS_V2_ENCERRAMENTO.md`.
