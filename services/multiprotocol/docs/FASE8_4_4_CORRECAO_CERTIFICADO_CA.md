# Fase 8.4.4 — Correção do certificado CA do laboratório (Python 3.14)

## Sintoma observado

- Regressão `before` aprovada, `preflight` aprovado.
- `fase8_4_4_online.py apply` inicia, consulta `getClient`, e retorna `INCONCLUSIVO`.
- Mosquitto 8884 registra `ssl/tls alert certificate unknown` quando o cliente Python tenta autenticar.
- `regressao_fase8_4_4.py after` rejeita corretamente o marco ainda não concluído.

O script de preparação 8.4.2 gerou a CA com `openssl req -x509` sem `keyUsage` explícito. Python 3.13+ ativa `VERIFY_X509_STRICT` por padrão. A validação X.509 estrita requer `keyUsage` de uma CA com `keyCertSign`. O `mosquitto_ctrl` anteriormente podia funcionar com essa CA enquanto o Python 3.14 não.

## Procedimento seguro no Arch

Não reinicialize `fase8_4_2_lab.py preparar` nem `provisionar`, não restaure snapshots e não execute `apply` pela segunda vez antes da análise do marcador.

No Terminal A:

```bash
cd ~/server/services/multiprotocol
python3 tests/test_fase8_4_4_corrigir_ca.py
python3 scripts/fase8_4_4_corrigir_ca.py diagnosticar
python3 scripts/fase8_4_4_online.py preflight
```

A correção pode ser feita **somente** se `Marcador 8.4.4: ausente`, `OpenSSL X509 estrito: REPROVADO` e o Python TLS 8884 estiver reprovado. Caso contrário, pare e revise o estado.

```bash
python3 scripts/fase8_4_4_corrigir_ca.py corrigir
python3 scripts/fase8_4_4_corrigir_ca.py diagnosticar
python3 scripts/fase8_4_4_online.py preflight
```

O comando de reparo reemite **somente `pki/ca.crt`**, usando `pki/ca.key` existente, com `basicConstraints=CA:TRUE` e `keyUsage=keyCertSign,cRLSign`. Antes de trocar o arquivo, verifica assinatura do certificado de servidor preexistente, subject, chave pública, hostname e IP sob `openssl verify -x509_strict`. Cria backup privado `pki/ca.crt.pre-8-4-4-strict.backup` (0600), sem sobrescrever backups existentes, troca atomicamente o certificado público e realiza handshake com Python estrito. Não altera `server.crt`, `server.key`, `ca.key`, `dynamic-security.json`, `clients/*.opts`, identidades nem o broker 8883. Não reinicia o broker 8884.

Se `corrigir` der erro, não execute `apply`, não repita o reparo sem diagnóstico e preserve os arquivos privados.

## Depois da aprovação do TLS

O marco de rotação não estará concluído apenas porque o TLS foi corrigido. Se a correção retornar sucesso e os marcadores permanecerem ausentes, execute **somente após revisão dos resultados:**

```bash
python3 scripts/fase8_4_4_online.py apply
# APENAS se apply terminar com APROVADO
python3 scripts/regressao_fase8_4_4.py after
```

Se houver um marco `prepared`, `rotation-requested`, `rotation-verified`, `disable-requested` ou `completed`, pare; a recuperação é separada e não se deve repetir `apply`.

## Segurança

- Todas as operações são locais ao Arch Linux. Nunca use `sudo`.
- Nunca publique `~/.config/rust-server/phase8-4-2-lab/`, senhas, opções de clientes, backups ou chaves em chat/GitHub.
- O reparo não desliga validação de certificado, cadeia confiável nem hostname.
- O laboratório permanece em `127.0.0.1:8884`; o broker original `8883` não é modificado.
- O certificado da CA é de laboratório e tem validade curta (30 dias desde a reemissão). Planejar renovação de certificados antes do vencimento.

## Referências

- Python 3.13: https://docs.python.org/pt-br/3.13/whatsnew/3.13.html
- OpenSSL strict: https://docs.openssl.org/4.0/man1/openssl-verification-options/

## Correção preventiva no gerador 8.4.2

O patch também atualiza `scripts/fase8_4_2_lab.py` para que **novos** laboratórios emitam CA estrita com `keyUsage` apropriado desde a criação, e `tests/test_fase8_4_2_lab.py` passa a exigir `openssl verify -x509_strict` no teste de preparação. **Instalar os dois arquivos não reexecuta `preparar`** nem altera o laboratório atual. Somente o comando explícito `fase8_4_4_corrigir_ca.py corrigir` reemite a CA do laboratório já existente.
