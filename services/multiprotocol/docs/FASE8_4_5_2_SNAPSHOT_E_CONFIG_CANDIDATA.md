# Rust-Server — Fase 8.4.5.2: Snapshot privado e configuração candidata (Arch Linux)

## Escopo e limites

Esta subfase implementa **preparação**, não migração. O broker legado `127.0.0.1:8883` permanece com `password_file`, ACL e TLS existentes; o laboratório Dynamic Security `127.0.0.1:8884` permanece intacto.

- Não usa `systemctl`, `kill`, `mosquitto_ctrl`, `mosquitto_passwd`, `git`, `sudo` nem altera processos.
- Não edita nenhum arquivo de origem nem `dynamic-security.json` do laboratório. O snapshot é escrito **exclusivamente fora do repositório** em `~/server_backups/fase8_4_5_2/`.
- O candidato usa **127.0.0.1:8895** e caminhos que referenciam **cópias no snapshot**; **não execute** o broker candidato nesta subfase.
- O candidato contém uma cópia do estado Dynamic Security do **laboratório**, **não uma migração de identidades**. Seus usuários/ACLs não são declarados equivalentes aos do `8883`. A paridade real depende da Fase 8.4.5.4.
- Não existe procedimento de rollback operacional na 8.4.5.2. `simular-restauracao` apenas confirma a recuperação de arquivos para um diretório temporário privado, sem tocar no broker.
- A decisão de corte para `8883` continua bloqueada até auditorias de segurança, CI/Git, paridade e rollback operacional aprovados.

## Dependências

Arch Linux, Python 3.14 e script aprovado `scripts/fase8_4_5_1_auditoria.py`. Execute como usuário proprietário da configuração, **sem `sudo`**. O script chama a lógica de auditoria da Fase 8.4.5.1 antes de criar snapshots. Os brokers podem estar parados ou ativos, desde que a configuração e os arquivos persistidos estejam consistentes. Não há conexões aos listeners.

A leitura do `dynamic-security.json` quando o broker está ativo verifica estabilidade do arquivo em duas leituras, **mas não prova** uma fotografia atômica do estado em memória do plugin. Se o plugin modificar o arquivo durante a cópia, a operação pode ser bloqueada. Para aceitar a recuperação operacional será necessário congelar o estado com processo controlado na 8.4.5.3.

## Arquivos inventariados (20 arquivos)

**Original 8883 (9):** configuração Mosquitto, `passwords`, `acl`, `devices.json`, tokens legados `mqtt-bridge.token` e `mqtt-lab.token`, `certs/ca.crt`, `certs/localhost.crt`, `certs/localhost.key`.

**Lab 8884 (11):** `mosquitto-lab.conf`, `dynamic-security.json`, `provisioned.json`, marcador da 8.4.4, `pki/ca.crt`, `pki/ca.key`, `pki/server.crt`, `pki/server.key`, e três `clients/*.opts`.

Os arquivos privados de origem têm modo `0600`, proprietário correto e não podem ser links simbólicos/hardlinks. O diretório de destino é criado com `0700`, arquivos com `0600`. A verificação SHA-256 compara as cópias com manifesto privado. Nomes das identidades e conteúdo de segredos não são exibidos pelo script.

**Atenção:** o snapshot **contém chaves privadas, senhas e credenciais ativas**; não abra o manifesto nem os arquivos para compartilhar aqui, não envie o snapshot por chat, não compacte em `~/Downloads`, não versione no Git e não sincronize sem política de backup criptografado. A estrutura não é criptografada em repouso pelo script: a proteção local é baseada em permissões do sistema de arquivos.

## Instalação do patch

No **Terminal A**, a partir do repositório:

```bash
cd ~/server/services/multiprotocol

git branch --show-current  # consultar apenas; NAO mudar a branch

unzip -o ~/Downloads/fase8-4-5-2-snapshot-candidato-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .
```

A branch registrada nos logs anteriores é `feature/fase8-4-inventory-dynsec` (sem hífen entre `fase` e `8`). O script **não altera Git**.

## Testes isolados e preflight

```bash
python3 -B tests/test_fase8_4_5_2_preparar.py
python3 -B scripts/fase8_4_5_2_preparar.py preflight
```

O preflight **não cria diretórios**, não altera arquivos, não se conecta aos brokers e não imprime segredos. Se houver BLOQUEIO, não execute `preparar`.

## Criar snapshot e candidato

```bash
python3 -B scripts/fase8_4_5_2_preparar.py preparar
```

Espere por:

```text
APROVADO: snapshot privado criado e verificado (20 arquivos).
SNAPSHOT=/home/arch/server_backups/fase8_4_5_2/snapshot-<identificador>
CANDIDATO: somente listener 127.0.0.1:8895; NAO executar broker nesta subfase.
```

Anote o valor completo de `SNAPSHOT` impresso **em seu terminal**. Um caminho de exemplo não é um snapshot real. O script não sobrescreve snapshots existentes. Caso ocorra falha inesperada durante a escrita, um diretório `.incompleto-8452-*` privado pode permanecer: não o trate como snapshot válido e não o exponha.

## Verificar e simular restauração de arquivos

Substitua a variável pelo caminho **exato** emitido no seu terminal:

```bash
SNAPSHOT='/home/arch/server_backups/fase8_4_5_2/snapshot-IDENTIFICADOR_REAL'
python3 -B scripts/fase8_4_5_2_preparar.py verificar --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_2_preparar.py simular-restauracao --snapshot "$SNAPSHOT"
```

O comando `simular-restauracao` copia os 20 arquivos apenas para diretório privado temporário, verifica hashes e apaga esse diretório ao finalizar. Não restaura o broker 8883/8884.

## Teste sintático opcional (Mosquitto 2.1+)

```bash
python3 -B scripts/fase8_4_5_2_preparar.py validar-config --snapshot "$SNAPSHOT"
```

Usa `mosquitto --test-config -c ...`, que na versão 2.1 verifica sintaxe e **não inicia** o serviço nem vincula a porta. A saída bruta é suprimida para evitar expor caminhos ou valores. A verificação sintática não demonstra autenticidade, paridade de ACL, TLS nem funcionamento operacional. Se o comando falhar, não edite a configuração original.

Referência: https://mosquitto.org/man/mosquitto-8.html

## Critérios de aceite

1. Regressão unitária 8.4.5.2 aprovada em ambiente fictício.
2. `preflight` e `preparar` aprovados no Arch, com snapshot privado de 20 arquivos e manifesto SHA-256.
3. `verificar`, `simular-restauracao` e `validar-config` aprovados, se disponível.
4. Broker original 8883 e laboratório 8884 não modificados. É permitido confirmar passivamente portas por `ss -lntp`.
5. Arquivos sensíveis permanecem fora do Git; auditoria de Git/CI ocorre no chat correspondente.

## Próximo passo — 8.4.5.3

Simular **recuperação operacional** em broker separado e verificar comportamento de autenticação, ACL, Client ID, certificados e retorno ao estado conhecido. **Nunca restaurar `dynamic-security.json` diretamente sobre um broker ativo**; o plugin tem estado em memória e gravações próprias. O corte real para `8883` só poderá ser avaliado na 8.4.5.5 após aceites adicionais.

## Referências

- Eclipse Mosquitto 2.1 `plugin_load` e `plugin_use`: https://mosquitto.org/documentation/listeners/per-listener-settings/
- Dynamic Security: https://mosquitto.org/documentation/dynamic-security/
- `mosquitto --test-config`: https://mosquitto.org/man/mosquitto-8.html
