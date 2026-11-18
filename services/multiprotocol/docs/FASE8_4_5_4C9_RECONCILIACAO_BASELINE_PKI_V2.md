# Fase 8.4.5.4-C.9 — Reconciliação documental do baseline PKI v2

**Escopo:** vínculo entre o snapshot C.2 histórico (29/10/2026) e o snapshot C.2 pós-renovação (10/11/2026), **sem corte 8883**, sem modificar brokers, senhas, ACL ou índices anteriores.

## Premissas verificadas pelo usuário

- Snapshot antigo: `snapshot-20261029T165042Z-1aa693fc4484`.
- Snapshot novo: `snapshot-20261110T192516Z-59cf28e102d1`.
- Novo C.2: verificou 20 arquivos, recuperou 20 em ensaio isolado, validou configuração candidata; a C.3 confirmou 20/20 origens atuais.
- Comparação de 20 fontes: 17 iguais; somente `lab/pki/ca.crt`, `lab/pki/server.crt`, `lab/pki/server.key` diferem.
- Os três arquivos divergentes foram conferidos byte a byte contra a PKI v2 e o certificado do servidor passou em `openssl verify`.

## O que o controlador C.9 realmente implementa

O módulo `scripts/fase8_4_5_4c9_reconciliacao_baseline.py` usa as funções **originais** `phase2.verify`, `phase2.sources`, `phase2.check_regular` e `phase3.assert_origins_match`. Ele:

1. Valida separadamente os dois snapshots C.2 e sua integridade interna.
2. Verifica que a origem **atual** ainda corresponde integralmente ao snapshot novo.
3. Compara **todos os 20** pares de arquivos históricos e atuais e exige exatamente três diferenças permitidas, sem imprimir conteúdo nem hash de chaves.
4. Confere esses três arquivos com o staging aprovado da PKI v2.
5. Lê em modo somente leitura C.4, C.6, C.7 e C.8 privados, conferindo referências históricas ao manifesto e as condições **NOT_GRANTED / FORBIDDEN**.
6. Cria uma **nova** trilha C.9 privada de auditoria em `~/.config/rust-server/phase8-4-5-4c/reconciliacao-baseline-c9.json`, modo `0600`, somente por criação exclusiva; não reescreve registros existentes.
7. Mantém as 21 pendências C-V1 e todas as aprovações externas como pendentes.

**Limite:** o C.9 é uma **reconciliação de proveniência** (testemunho). Ele **não é a migração dos registros C.4/C.6/C.7/C.8** para o novo fingerprint e **não desbloqueia** os comandos originais que ainda estão atrelados ao snapshot de outubro. Isso exigirá uma etapa posterior, com versões e caminhos independentes dos índices e reexecução dos controles C.4→C.7. Nenhuma evidência do cenário B pode se transformar em prova do cenário A.

## Instalação sem sobrescrita

Na raiz do repositório:

```bash
cd ~/server
ZIP="$HOME/Downloads/Rust-Server-Fase8_4_5_4C9-Reconciliacao-Baseline.zip"
unzip -t "$ZIP"
unzip -n "$ZIP" -d "$HOME/server"
cd ~/server/services/multiprotocol
python3 -B tests/test_fase8_4_5_4c9_reconciliacao_baseline.py
```

Se algum arquivo existente for ignorado por `unzip -n`, **não presuma** que a instalação atualizou o módulo: compare as versões antes de prosseguir.

## Verificações de execução

```bash
C9="scripts/fase8_4_5_4c9_reconciliacao_baseline.py"
python3 -B "$C9" preflight
```

Somente se o preflight **aprovar**, execute **uma vez**:

```bash
python3 -B "$C9" iniciar
python3 -B "$C9" verificar
```

O programa bloqueia diretórios privados sem `0700`, arquivos sem `0600`, diferenças de origem além dos três certificados/chaves, índices históricos sem fingerprint correto, versão de C.8 que conceda aprovação e qualquer divergência posterior do baseline novo. Um bloqueio requer investigação; **não altere os JSONs antigos ou seus fingerprints** para fazê-lo passar.

## Próxima etapa real — índices versionados

Depois da aprovação C.9:

- Projetar o armazenamento paralelo de C.4/C.6/C.7 e C.8 do fingerprint novo, **sem substituir** os nomes antigos, e com vínculo explícito à C.9.
- Criar novos índices vazios e novos documentos observacionais do cenário A; qualquer reutilização de uma evidência antiga exige revalidação e aprovação independente.
- Permanecem 21 pendências C-V1, revisão de Segurança, Git/CI, prontidão operacional, janela autorizada e novo snapshot final.
- **Jamais executar corte, rollback, rotação ou alteração no 8883 por essa subfase.**


## Correção v2 — leitura distinta de certificados e chave de staging

A implementação C.9 original chamava `phase2.check_regular(..., private=True)`
para os três arquivos TLS no staging. Isso exige o modo `0600` inclusive nos
certificados públicos, embora `ca.crt` e `server.crt` possam legitimamente
estar em `0640` ou `0644` dentro do diretório privado `0700`.

A correção utiliza `staging_artifact()` com leitura **somente leitura** e valida
que os arquivos sejam regulares, com proprietário esperado, tamanho restrito,
sem links simbólicos ou hardlinks e sem permissão de escrita para grupo/outros:

- `ca.crt`, `server.crt`: modos aceitos `0600`, `0640`, `0644`.
- `server.key`: **somente `0600`**.
- Diretório homologado de staging: **somente `0700`** e sem symlink.

Os bytes seguem comparados com o snapshot novo; não há dispensa de validação
criptográfica anterior, nem migração de índices ou corte MQTT.

Se o preflight ainda falhar, a mensagem indicará o arquivo ou classe do problema.
Nunca altere modo de chaves privadas para `0644`, nem execute como root.
