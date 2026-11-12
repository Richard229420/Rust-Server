# Fase 8.4.5.4-C.10 — registros versionados para cenário A (sem corte)

## Propósito e limites

Esta camada documental usa exclusivamente o testemunho C.9 **existente e íntegro** para criar uma nova geração de registros **independentes dos arquivos fixos históricos**. O controlador chama a auditoria original da C.9 novamente a cada ação; ela verifica os dois snapshots C.2, as origens C.3, as três mudanças TLS esperadas, o staging PKI v2 e os vínculos históricos C.4/C.6/C.7/C.8. Falhas bloqueiam as ações.

**C.10 não é migração nativa dos schemas C.4/C.6/C.7/C.8.** Os arquivos novos são um *plano versionado* e um índice C.10 utilizável para referências documentais; os controladores antigos continuam reconhecendo apenas os registros históricos. As verificações operacionais do cenário A, novas coletas C.7, revisão de Segurança/Git/CI e validação independente de evidências ainda precisam ser executadas. Não há qualquer transferência de aprovação.

A C.10 **não** instala serviços, modifica certificados, abre sockets, altera broker 8883/8884, executa comandos MQTT, altera o estado DynSec, modifica Git ou reativa `device-sensor01`.

## Saídas

Diretório: `~/.config/rust-server/phase8-4-5-4c/versions/<SHA256-do-manifesto-C2-novo>/` (modo `0700`). Os seguintes JSON ficam em `0600`:

- `manifesto-c10.json`: testemunho da versão, SHA-256 do C.9 e hashes de todos os quatro registros de planejamento.
- `c4-planejamento.json`: três identidades candidatas a verificação, com `runtime=NOT_CONFIRMED`.
- `c6-indice-vazio.json`: índice de planejamento sem evidências transferidas.
- `c7-coleta-pendente.json`: coleta operacional **não realizada**.
- `c8-pendencias.json`: os 21 critérios C-V1 originais, todos com revisão pendente.
- `registro-evidencias-c10.json`: referências opacas e hashes de documentos redigidos, inicialmente vazio; pode receber metadados, **nunca aprovação**.

A C.10 usa um manifesto imutável (verificado contra os quatro registros estáticos) e um índice de evidências mutável separado. Criações são exclusivas; não há sobrescrita de uma versão existente. Uma falha durante a criação deixa uma pasta incompleta privada para inspeção, sem tentar corrigi-la por conta própria.

## Instalação

Copie somente os três arquivos do ZIP para `~/server/services/multiprotocol/` com `unzip -n`, depois execute:

```bash
cd ~/server/services/multiprotocol
python3 -B tests/test_fase8_4_5_4c10_indices_versionados.py
python3 -B scripts/fase8_4_5_4c10_indices_versionados.py preflight
```

Se o preflight passar, os passos de criação/validação são:

```bash
python3 -B scripts/fase8_4_5_4c10_indices_versionados.py iniciar
python3 -B scripts/fase8_4_5_4c10_indices_versionados.py verificar
python3 -B scripts/fase8_4_5_4c10_indices_versionados.py status
python3 -B scripts/fase8_4_5_4c10_indices_versionados.py roteiro
```

**Não repita `iniciar`** se já existir pasta versionada. Não rode com `sudo`.

## Registro de uma evidência real do cenário A

Somente após coletar documento operacional **redigido, armazenado e protegido fora deste índice**, calcule localmente seu SHA-256 e associe um identificador opaco:

```bash
DOCUMENTO="$HOME/caminho-privado/documento-redigido.md"
sha256sum -- "$DOCUMENTO"  # nunca utilizar documento contendo segredos

python3 -B scripts/fase8_4_5_4c10_indices_versionados.py registrar \
  --item BRI-01 --referencia EV-A-BRIDGE0001 \
  --sha256 'COLE_O_HASH_SHA256_DO_DOCUMENTO_REDIGIDO' \
  --tipo inventario-redigido
```

O registro contém somente ID da pendência, referência opaca, SHA-256, tipo e timestamp. *Não* autentica a origem, não atesta execução real e não baixa nenhuma das 21 pendências. O SHA-256 de documento privado pode revelar correlação, por isso o índice permanece privado e não deve ser publicado. **Não use o exemplo literal de hash**: substitua-o pelo SHA-256 hexadecimal de 64 caracteres do seu próprio documento redigido. Valores de senha, token, Client ID sensível, chaves, arquivos de opções com credenciais e inventários não redigidos não entram aqui.

## Gates para fases seguintes

Antes de encerrar C-V1: evidência real da bridge, política e operadores `lab`, existência e Client ID de `device-sensor02`, rotação/rollback por cliente real fora de produção, custodiante, janela, monitoramento, revisão Git/CI e de Segurança. Os resultados do laboratório 8884 (B) não comprovam os clientes do cenário A. A migração do 8883 permanece proibida até deliberação externa explícita.

## Testes e escopo de validação

Os testes `unittest` usam diretórios temporários, nunca o home do operador, os brokers ou os snapshots reais. A prova de funcionamento integrado só ocorre quando `preflight` e `verificar` passam no host Arch Linux do usuário.
