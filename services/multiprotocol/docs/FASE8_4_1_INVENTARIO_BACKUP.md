# Fase 8.4.1 — Inventário e backup privado (Arch Linux)

## Escopo e estado de referência

- Fonte única de execução: Arch Linux, `~/server`.
- HTTP: `127.0.0.1:8080`; gateway HTTPS: `127.0.0.1:8443`.
- Mosquitto legado TLS+ACL: `127.0.0.1:8883`; TCP/TLS: `127.0.0.1:7001`.
- Fase 8.3: `sensor01` revogado; `sensor02` ativo com rotação de senha.
- Não usar instalações, bancos, chaves ou certificados do Debian.
- **Não habilitar o plugin Dynamic Security no broker real nesta fase.**

## Plugin no Mosquitto 2.1.2-2

A lista oficial do pacote Arch Linux inclui `/usr/lib/mosquitto_dynamic_security.so`.
A pesquisa anterior por `dynamic-security` (hífen) não o encontrava; o nome real usa `dynamic_security`.
Confirme localmente:

```bash
pacman -Ql mosquitto | rg 'mosquitto_dynamic_security\.so|mosquitto_ctrl'
```

O Dynamic Security não é habilitado automaticamente. **Não adicione `plugin`, `plugin_load` ou `global_plugin` ao `mosquitto.conf` atual** sem a Fase 8.4.2.

## Scripts de aceitação

Executar como usuário `arch`, sem `sudo`, no diretório do serviço:

```bash
cd ~/server/services/multiprotocol
python3 scripts/fase8_4_1_inventario_backup.py inventario
python3 tests/test_fase8_4_1_snapshot.py
python3 scripts/fase8_4_1_inventario_backup.py backup
python3 scripts/fase8_4_1_inventario_backup.py verificar
python3 scripts/fase8_4_1_inventario_backup.py simular-restauracao
```

Não é necessário parar os servidores para inventariar ou copiar seus arquivos estáticos. **Não rode `create`, `rotate`, `revoke` nem `init` durante o backup**; uma alteração de conteúdo detectada faz o script abortar. Sessões MQTT e mensagens em memória não são capturadas.

Destino padrão: `~/server_backups/fase8_4_1/<data-hora>-<sufixo>/`. As pastas têm permissão 0700 e arquivos 0600. O backup contém segredos e material privado: **não anexar ao chat, não publicar no Git, não colocar em pendrive sem criptografia.**

Arquivos necessários: `~/.config/rust-server/mosquitto/{mosquitto.conf,passwords,acl,devices.json}`, `~/.config/rust-server/{mqtt-bridge.token,mqtt-lab.token}`, `~/server/services/multiprotocol/certs/{ca.crt,localhost.crt,localhost.key}`. Se existirem, `certs/ca.key`, `certs/ca.pem` e `device-tokens/*.token` também são copiados. Histórico de snapshots anteriores e banco SQLite do HTTP **não** entram neste backup: protegê-los em rotinas próprias.

O manifesto inclui hashes SHA-256 e nomes de dispositivos/estados, nunca os valores das senhas. O programa verifica integridade e restaura apenas em diretório de teste privado; não sobrescreve a configuração em uso.

## Rollback operacional (roteiro, não executar agora)

**Somente se a Fase 8.4.2+ falhar ou for necessário restaurar a Fase 8.3:**

1. Manter o snapshot privado da 8.4.1 e validar com `verificar --snapshot <caminho>`.
2. Encerrar **primeiro** o multiprotocolo e depois o broker MQTT; confirmar `ss -lntp | rg ':(8443|7001|8883)\b'` sem `LISTEN` desses serviços.
3. Criar um segundo backup, agora do estado modificado, antes de reverter; nunca misturar arquivos de duas versões.
4. Restaurar o conjunto completo do mesmo snapshot (arquivos `mosquitto/*`, tokens e certificados) nos caminhos documentados no manifesto, com propriedade correta e permissões 0700/0600; conferir referências no `mosquitto.conf`. Não restaurar só o `passwords` sem ACL/inventário.
5. Reiniciar Mosquitto e multiprotocolo nessa ordem, em loopback apenas. Reexecutar 8.2 ACL, 8.1 TCP/TLS, 8.3 testes com dispositivos válidos e HTTP/HTTPS.
6. Se houver divergência no inventário/ACL ou hashes inválidos, **não iniciar o broker** antes de reconciliar o estado. Revogação/rotação posterior ao snapshot será revertida e deve ser reaplicada antes de expor qualquer listener.

Este procedimento **não é recuperação automática** nem protege contra falha física do disco; manter backup adicional criptografado fora da máquina, sem expor segredos.

## Critérios de encerramento

- [ ] Biblioteca `mosquitto_dynamic_security.so` encontrada no pacote local.
- [ ] Inventário demonstra `sensor01=revoked`, `sensor02=active` e conjunto esperado de arquivos.
- [ ] Backup privado concluído com manifesto e hashes válidos.
- [ ] `verificar` e `simular-restauracao` aprovados.
- [ ] Nenhuma alteração nas portas 8080, 8443, 8883 ou 7001, no HTTP, no SQLite ou no broker real.
- [ ] Arquivos sensíveis excluídos do staging e do Git.

Referências: https://archlinux.org/packages/extra/x86_64/mosquitto/files/ ; https://mosquitto.org/documentation/dynamic-security/ ; https://mosquitto.org/documentation/listeners/per-listener-settings/ .
