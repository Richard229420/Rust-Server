# Rust-Server — Fase 8.4.5.1: Inventário pré-migração (somente leitura)

**Escopo:** auditoria local de pré-requisitos para a futura migração do Mosquitto legado `127.0.0.1:8883` para autenticação Dynamic Security. **Não constitui autorização de corte** e não migra nada.

## Dependências e estado esperado

- Arch Linux, Python 3.14+ (stdlib), `ss` do iproute2 (verificação opcional de listeners).
- Executar como usuário `arch` (ou outro usuário dono dos arquivos), **sem `sudo`**.
- Projeto em `~/server/services/multiprotocol`, configurações privadas em `~/.config/rust-server`.
- Broker `8883` usando a ACL e o `password_file` da Fase 8.3, com `sensor01` revogado e `sensor02` ativo.
- Laboratório `8884` da Fase 8.4.2, com Dynamic Security carregado e marcador `fase8_4_4_state.json` concluído após a Fase 8.4.4.
- Biblioteca `/usr/lib/mosquitto_dynamic_security.so` presente.

## Como executar

Os Terminais B e C **podem permanecer executando os brokers**, mas o auditor também funciona com os processos parados. Não executa conexões TLS/MQTT nem `mosquitto_ctrl`.

No **Terminal A**:

```bash
cd ~/server/services/multiprotocol
python3 tests/test_fase8_4_5_1_auditoria.py
python3 scripts/fase8_4_5_1_auditoria.py
```

Testes com fixtures artificiais, sem acesso às credenciais reais:

```bash
python3 tests/test_fase8_4_5_1_auditoria.py
```

Modo para teste desconectado do host (sem invocar `ss`):

```bash
python3 scripts/fase8_4_5_1_auditoria.py --no-runtime
```

O relatório vai exclusivamente para `stdout`. **Não é gravado nenhum arquivo**. Para coletar evidências, revisar a saída antes de redirecioná-la para uma área privada fora do Git.

## Quais verificações são realizadas

1. **Legado 8883:** configuração privada, listener `127.0.0.1:8883`, anonimato proibido, arquivos de senha/ACL esperados, TLS configurado, ausência de plugin de autenticação adicional e validação de `devices.json`.
2. **Reconciliar identidades:** verifica que `bridge`, `lab` e os dispositivos `active` são as únicas contas presentes no arquivo de senhas; dispositivos revogados não podem aparecer como contas ativas. Compara ACLs legadas exatamente com as permissões restritas estabelecidas na Fase 8.3.
3. **Material TLS 8883:** verifica existência, dono, modos de acesso e ausência de links simbólicos, sem ler chaves privadas.
4. **Laboratório 8884:** configuração isolada `plugin_load`/`plugin_use`, listener loopback, anonimato negado, plugin esperado, `dynamic-security.json`, arquivos `.opts` e certificados/chaves presentes com permissões corretas.
5. **Marco 8.4.4:** lê somente os campos esperados de status do marcador privado (não o conteúdo do Dynamic Security) e confirma `completed`.
6. **Listeners passivamente:** `ss -H -lnt`, sem criar conexão. Mostra se cada porta está em loopback, parada, exposta ou indisponível para consulta.

## O que o auditor NÃO faz

- Não edita nenhuma configuração e não altera `dynamic-security.json`.
- Não executa `mosquitto_ctrl`, `mosquitto_passwd`, `systemctl`, `kill`, `openssl` ou comandos que controlam o broker.
- Não conecta a portas nem solicita credenciais.
- Não lê `.opts`, chaves privadas nem o conteúdo de `dynamic-security.json`. Os hashes legados são lidos em memória apenas para validar a lista de usuários, sem exibição.
- Não prova o estado **em memória** dos usuários do plugin, permissões efetivas em execução, criptografia TLS válida, backup recuperável ou rollback operacional.
- Não acessa repositórios Git remotos nem envia dados à rede.

## Interpretação

- `APROVADO:` regra local atendida.
- `BLOQUEIO:` inconsistência que exige investigação antes da Fase 8.4.5.2.
- `PENDENTE:` assunto intencionalmente reservado a uma fase posterior.
- **Exit code 0:** zero bloqueios locais; autorizado apenas *preparar* a próxima subfase.
- **Exit code 2:** um ou mais bloqueios; **não corrigir automaticamente**.

Mesmo com exit code 0, a migração operacional na porta 8883 continua bloqueada até aprovação de backup + restauração, paridade de identidades/ACLs, CI/Git e auditoria de Chaves e Segurança.

## Critérios de aceite 8.4.5.1

- Auditor com código público separado dos arquivos privados.
- Suíte isolada de regressões passando (14 testes no pacote inicial).
- Execução local no Arch com `bloqueios=0` **ou** identificação e tratamento documentado dos bloqueios, sem modificar o broker original.
- Relatório revisado sem vazamentos de dados sensíveis.
- Aprovação para planejar Fase 8.4.5.2, **não** para fazer cutover de `8883`.

## Referências técnicas

- Eclipse Mosquitto — [Plugin e listeners no Mosquitto 2.1](https://github.com/eclipse-mosquitto/mosquitto/blob/master/www/pages/documentation/listeners/per_listener_settings.md).
- Eclipse Mosquitto — [Dynamic Security](https://mosquitto.org/documentation/dynamic-security/).

**Nota:** na versão 2.1, `plugin_load` carrega a biblioteca e `plugin_use` a associa a um listener. O arquivo `dynamic-security.json` contém dados sensíveis e é atualizado pelo broker durante operações normais; seu estado no disco não substitui consulta autorizada e testes reais contra o plugin.
