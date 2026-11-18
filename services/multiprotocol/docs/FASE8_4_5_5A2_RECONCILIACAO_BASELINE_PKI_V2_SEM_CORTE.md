# Rust-Server — Fase 8.4.5.5-A.2: reconciliação do baseline PKI v2, sem corte

## Objetivo

Registrar um **candidato privado e versionado** que evidencie a diferença entre o snapshot histórico de 29/10/2026 e o estado atual da PKI do laboratório. **A.2 não substitui** a Fase 8.4.5.2, não aceita o candidato como snapshot de produção, não autoriza migração para `8883` e não modifica o repositório nem os brokers.

Contexto já observado no Arch, enviado pelo operador:

- Snapshot imutável: `~/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484`; integridade de 20 arquivos aprovada.
- Comparação histórica: **17 iguais e exatamente três divergentes** (`lab/pki/ca.crt`, `lab/pki/server.crt`, `lab/pki/server.key`). Não restabelecer os arquivos antigos por cima dos novos.
- Certificado atual válido de 08/11/2026 a 07/05/2027 segundo o OpenSSL do host; **certificado do servidor e chave do servidor** correspondem, e `sslserver`, `localhost` e `127.0.0.1` foram aprovados. **A correspondência da chave privada `lab/pki/ca.key` com o certificado atual da CA não foi comprovada.** Como `ca.key` permaneceu entre os 17 arquivos iguais, sua custódia e compatibilidade com a nova CA exigem avaliação de Segurança antes de qualquer baseline operacional.
- Cadastro C-v1 com **21 pendências**, Cenário A principal, B laboratório; `device-sensor01` revogado. A existência de um arquivo `device-sensor01.opts` **no snapshot histórico** é esperada e **não autoriza** reativação.
- A etapa 8.4.5.5-A original bloqueou corretamente em `assert_origins_match()`; esse bloqueio **permanece**, até uma decisão formal de transição do baseline.

## Instalação no Arch Linux

Use somente uma conta de usuário normal, **nunca `sudo`**:

```bash
cd ~/server/services/multiprotocol
pwd
unzip -o \
  ~/Downloads/fase8-4-5-5a2-reconciliacao-pki-v2-sem-corte-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .
python3 -B tests/test_fase8_4_5_5a2_reconciliar_pki.py
```

Os testes usam certificados temporários **fictícios** gerados com OpenSSL e não leem certificados de produção. O `openssl` do host é necessário para a ferramenta e os testes.

```bash
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"

python3 -B scripts/fase8_4_5_5a2_reconciliar_pki.py \
  preflight --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_5a2_reconciliar_pki.py \
  inspecionar --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_5a2_reconciliar_pki.py \
  plano --snapshot "$SNAPSHOT"
```

`preflight`, `inspecionar` e `plano` **não escrevem** nas configurações nem nos cadastros e não iniciam brokers. O `preflight` só aprova a preparação documental da **A.2**, nunca o preflight da **A.5** e nunca a operação real.

## Criar um candidato (uma vez, após conferência)

A ação `criar` grava **20 arquivos privados**, incluindo cópias das **chaves privadas**, em `~/server_backups/fase8_4_5_5a2/`. A pasta e todas as subpastas têm permissões `0700`, arquivos `0600`. Não mostre o manifesto completo nem copie os segredos para Git, chat, tickets ou armazenamento público.

```bash
python3 -B scripts/fase8_4_5_5a2_reconciliar_pki.py \
  criar --snapshot "$SNAPSHOT"
```

O programa retorna um caminho único `CANDIDATO=...`, criado sem sobrescrever qualquer candidato preexistente. **Guarde esse caminho** e verifique a cópia com:

```bash
CANDIDATO="$HOME/server_backups/fase8_4_5_5a2/candidato-<IDENTIFICADOR_REAL>"
python3 -B scripts/fase8_4_5_5a2_reconciliar_pki.py \
  verificar --snapshot "$SNAPSHOT" --candidato "$CANDIDATO"
```

Substitua o placeholder pelo identificador **exato** da saída; não invente um ID. Não rode `criar` de novo se já houver um candidato validado.

## Proteções

- Exige integridade do snapshot histórico da 8.4.5.2 e preserva seu manifesto e candidato originais.
- Exige que **somente** os três arquivos da PKI do laboratório tenham novos hashes, e que os outros 17 permaneçam idênticos aos históricos.
- Valida cadeia TLS, finalidade de servidor, `localhost`, `127.0.0.1`, validade temporal e **chave do servidor** correspondente; não imprime dados confidenciais nem OpenSSL stderr. **Não valida** a chave privada da CA nem a configuração TLS de clientes reais.
- Exige cadastros históricos C-v1, C-v2, C.6 e C.7 íntegros, referenciando o fingerprint original, com **21 pendências**. Não tenta contornar nem migrar esses cadastros.
- Não cria uma configuração do Mosquitto para o novo candidato, nem o torna legível pelas ferramentas antigas de corte.
- Cria candidato com novo manifesto de fase própria, carimbado `candidate-unapproved`, `NO-GO`, `cutover_authorized=false`, três aprovações `false` e proveniência `pending-independent-review`.
- Detecta alterações das origens durante a comparação e criação; em erro, não apaga silenciosamente cópias privadas parciais. Podem restar diretórios `.incompleto-*` com material sensível para revisão manual.

## Critérios **não** encerrados pela A.2

1. Proveniência assinada/revisada da renovação PKI v2: quem emitiu, aprovou, onde ficam as evidências redigidas, se a CA atual é a pretendida para os clientes. **A verificação OpenSSL não prova essa cadeia operacional de custódia.**
2. Decisão independente de Segurança sobre a aceitação da PKI v2 e a estratégia de distribuição e rotação dos trust stores dos clientes.
3. Decisão formal de como migrar o **vínculo do baseline** nos registros históricos C-v1/C-v2/C.6/C.7 e o plano A.5: não alterar silenciosamente hashes nem usar o candidato A.2 como argumento `--snapshot` das ferramentas antigas.
4. Testes dos clientes operacionais do Cenário A, homologação B, plano de rollback por cliente, 21 pendências, janela e snapshot final atualizado sob manutenção aprovada.
5. Revisão Git/CI das alterações desta etapa, sem merge ou publicação automática.

**Decisão nesta etapa: NO-GO. O corte MQTT `8883` continua proibido.**
