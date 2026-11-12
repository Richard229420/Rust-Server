# Fase 8.4.5.2 — correção do preflight para diretórios de backups

## Problema

Quando `~/server_backups/fase8_4_5_2` ainda não existe, a versão anterior do
`preflight` verifica arquivos e política, mas não valida o diretório intermediário
`~/server_backups`. O comando `preparar` faz essa validação ao tentar criar o
snapshot e pode retornar um bloqueio genérico.

## Mudanças

- `preflight` verifica todos os ancestrais **já existentes** do destino sem criar nada.
- A preparação continua exigindo diretórios privados (0700), propriedade do usuário,
  sem symlinks e fora do Git/configuração dos brokers.
- Mensagens de bloqueio `Block` passam a informar a classificação técnica conhecida,
  sem imprimir hashes, senhas, conteúdo de arquivos ou erros brutos do sistema.
- Incluídos dois testes: o preflight rejeita `~/server_backups` em 0755 e aceita 0700.
- Não altera a porta 8883, a porta 8884, contas MQTT nem certificados.

## Diagnóstico somente leitura

```bash
cd ~/server/services/multiprotocol
python3 -B tests/test_fase8_4_5_2_preparar.py
python3 -B scripts/fase8_4_5_2_preparar.py preflight
stat -c '%a %U %n' "$HOME/server_backups" 2>/dev/null || true
```

Se a saída for `BLOQUEIO: diretorio nao privado`, examine a propriedade e as
permissões de `~/server_backups`, sem copiar o conteúdo desse diretório.

## Remediação restrita, quando for 0755 e pertencer ao próprio usuário

```bash
p="$HOME/server_backups"
if [ -d "$p" ] && [ ! -L "$p" ] && [ "$(stat -c '%u' -- "$p")" = "$(id -u)" ]; then
  chmod 700 -- "$p"
  stat -c '%a %U %n' -- "$p"
else
  printf 'Nao alterar: diretorio ausente, link simbolico ou proprietario diferente.\n'
fi
```

Esta mudança apenas restringe acesso ao diretório de backups do usuário, sem
alterar seus arquivos internos. NÃO usar `sudo`, `chmod -R` ou `chown -R`.

Se houver outra classificação de bloqueio, investigue-a antes de tentar `preparar`
novamente. Uma tentativa anterior pode ter deixado `*.incompleto-*` sob o diretório
privado; **não elimine nem publique esses diretórios sem diagnóstico**.

## Após a aprovação

```bash
python3 -B scripts/fase8_4_5_2_preparar.py preflight
python3 -B scripts/fase8_4_5_2_preparar.py preparar
```

Não executar migração real nem iniciar a configuração candidata nessa subfase.
