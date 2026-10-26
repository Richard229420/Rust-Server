# Fase 8.3 — Identidades MQTT por dispositivo (laboratório local)

## Objetivo e limites

Sobre a versão **8.2 / `rust-server-multiprotocolo` v0.2.2** já testada (sem alterar o banco SQLite):

- Provisão de contas independentes `device-<ID>` para sensores, com segredo aleatório de 288 bits gerado por `secrets.token_urlsafe(36)`.
- Hash por dispositivo usando `mosquitto_passwd -U` em **tmpfs `/dev/shm`**, sem expor o segredo na linha de comando da ferramenta de hashing. Nunca executar `-U` sobre o arquivo `passwords` de produção.
- ACL *allowlist* por sensor: `topic write lab/sensors/<ID>/#` e `topic read bus/sensors/<ID>/#`.
- A conta compartilhada `lab` perde o acesso global `lab/sensors/#` e `bus/sensors/#`: permanece limitada a `lab/alerts` (escrita) e `bus/alerts` (leitura). Isso é uma **mudança intencional de compatibilidade**.
- `src/bridge.rs` rejeita nomes de sensores sem `ID/canal`, segmentos `.` e `..`, caracteres estranhos e IDs malformados. Não substitui a ACL, pois a bridge não recebe a identidade de origem autenticada pelo broker.
- Revogação (remove hash **e** ACL) e rotação de credencial; inventário JSON local com estados `active`/`revoked`, sem senhas.
- **Broker obrigatoriamente parado para mutações.** O reinício encerra sessões preexistentes — importante porque recarregar apenas `password_file` com SIGHUP **não** desconecta clientes já conectados.
- Cotas adicionais no Mosquitto: `max_packet_size 4096`, `max_connections 64`, `max_queued_messages 32`, `max_queued_bytes 32768`, `max_inflight_messages 10`, `max_qos 1`; remove `message_size_limit` obsoleto. Mantém listener TLS em loopback.
- Controle de concorrência por `flock`, cópias privadas de recuperação e escrita dos arquivos com substituição atômica individual (não transação multi-arquivo).

**Limitações importantes:** a conta legada `lab` agora é exclusiva de alertas. Sensores antigos que publicavam como `lab` em `lab/sensors/...` precisarão receber identidade individual. Não existe limitação de taxa por usuário no broker, mTLS, isolamento por client ID nem proteção completa contra DoS. Ainda não se recomenda expor os serviços à LAN. Os arquivos de ACL/password usam a configuração legada do Mosquitto 2.1 e precisam migrar para plugins antes de Mosquitto 3.0.

## Arquivos

- `scripts/gerenciar_dispositivos_fase8_3.py`: operações `init`, `create`, `rotate`, `revoke`, `list`.
- `src/bridge.rs`: validação adicional das rotas de sensores individuais, com testes Rust.
- `tests/test_phase8_3_manager.py`: testes offline simulados do CLI; não substituem o teste MQTT real.
- `scripts/test_phase8_3_devices.sh`: testes positivos e negativos com entrega MQTT real.
- `scripts/setup_phase8_2_mosquitto.sh`: recebe guarda que impede sobrescrever a fase 8.3 acidentalmente.
- Segredos/estado em `~/.config/rust-server/mosquitto/` e `~/.config/rust-server/device-tokens/` com permissões restritas; **nunca versionar**.

## Instalação no Arch Linux (somente após Fase 8.2 aprovada)

1. Em `~/server`, salve o estado no Git em `feature/fase8-3-device-security` (idealmente criada depois da integração da 8.2 à main).
2. Interrompa o Mosquitto no Terminal B com `Ctrl+C`. Interrompa a bridge Rust no Terminal C com `Ctrl+C` para evitar seu ciclo de reconexão; o HTTP original no A pode continuar.
3. A partir de `~/server/services/multiprotocol`, aplique o patch dos scripts e `src/bridge.rs` (faça backup antes), compile com `cargo check --all-targets` e rode `cargo test --all-targets`. Ao atualizar, `lab/sensors/temp` deixa de ser aceito na bridge; use `lab/sensors/sensor01/temperature`.
4. Inicialize:

```bash
cd ~/server/services/multiprotocol
python3 scripts/gerenciar_dispositivos_fase8_3.py init
python3 scripts/gerenciar_dispositivos_fase8_3.py create sensor01
python3 scripts/gerenciar_dispositivos_fase8_3.py create sensor02
python3 scripts/gerenciar_dispositivos_fase8_3.py list
```

Os segredos gerados ficam **temporariamente**, somente para distribuição ao sensor, em:

```text
~/.config/rust-server/device-tokens/sensor01.token
~/.config/rust-server/device-tokens/sensor02.token
```

Arquivos privados `0600`, não os cole em chat, terminal público ou Git. Depois de provisionar os sensores, apague as cópias locais de distribuição; para testá-las, execute o script antes de apagá-las. **Perda do segredo exige rotação**.

5. Terminal B:

```bash
cd ~/server/services/multiprotocol
bash scripts/run_phase8_2_mosquitto.sh
```

6. Terminal C:

```bash
cd ~/server/services/multiprotocol
source scripts/env_phase8.sh
cargo run
```

7. Terminal D:

```bash
cd ~/server/services/multiprotocol
source scripts/env_phase8.sh
bash scripts/test_phase8_2_acl.sh
bash scripts/test_phase8_3_devices.sh sensor01 sensor02
bash scripts/test_phase8_1_tcp_acl.sh
bash scripts/test_phase8_1_mqtt_auth.sh
```

Verifique o resultado `APROVADO` de cada teste. O cliente Mosquitto **2.1+** usa `-o` para receber parâmetros de autenticação em arquivo privado (`/dev/shm`) e evitar senhas na linha de comando do processo, melhorando os testes anteriores que utilizavam `-P`.

## Testar rotação

1. Pare o Terminal C e **pare o Terminal B**.
2. Salve o token antigo **somente se precisar demonstrar a rejeição do segredo anterior** e mantenha a cópia em local protegido.
3. Execute:

```bash
python3 scripts/gerenciar_dispositivos_fase8_3.py rotate sensor02
```

4. Reinicie B e C. Teste com o novo token. Para verificar rejeição do token antigo, use um cliente temporário (`mosquitto_pub -o <config-privada-antiga>`) e confirme que o CONNACK não é aceito. **Não exponha o token em `-P` ou em linha de comando.**

## Testar revogação completa

1. Com broker ainda ativo, faça (opcional, para teste de rejeição real) uma cópia privada do token **antes** de revogar, mas **pare B e C antes de alterar as contas**:

```bash
mkdir -p ~/.config/rust-server/revocation-test
chmod 700 ~/.config/rust-server/revocation-test
cp ~/.config/rust-server/device-tokens/sensor01.token ~/.config/rust-server/revocation-test/sensor01-OLD.token
chmod 600 ~/.config/rust-server/revocation-test/sensor01-OLD.token
```

2. Pare os terminais C e B; revogue:

```bash
cd ~/server/services/multiprotocol
python3 scripts/gerenciar_dispositivos_fase8_3.py revoke sensor01
python3 scripts/gerenciar_dispositivos_fase8_3.py list
```

3. Reinicie B e C. No Terminal D:

```bash
source scripts/env_phase8.sh
export RUST_SERVER_REVOKED_TOKEN_FILE="$HOME/.config/rust-server/revocation-test/sensor01-OLD.token"
bash scripts/test_phase8_3_devices.sh --revoked sensor01 sensor02
unset RUST_SERVER_REVOKED_TOKEN_FILE
rm -f "$HOME/.config/rust-server/revocation-test/sensor01-OLD.token"
```

O resultado positivo é `APROVADO: login revogado rejeitado, conta restante ativa.` O script sai com status `2` e `INCONCLUSIVO` se não receber cópia privada da senha antiga: o desaparecimento da conta no arquivo de senha, por si só, não testa autenticação real.

## Recuperação, falhas e mudanças futuras

Cada mutação cria snapshot em `~/.config/rust-server/mosquitto/backups-fase8-3/` contendo **hashes anteriores** e ACLs; mantenha permissões `0700/0600`. Se uma escrita falhar no meio (múltiplos arquivos são trocados separadamente), **não reinicie o broker**; restaure um snapshot completo e confira inventário, ACL e hashes, depois repita a operação. Nunca faça rollback de hashes antigos em ambiente exposto sem uma decisão consciente.

O CLI exige que o estado de ACL, contas e inventário estejam coerentes antes de mutações futuras, como proteção contra operações parciais.

O script de setup 8.2 agora se recusa a rodar quando existe `devices.json` para evitar perda de contas de sensores.

## Próxima etapa recomendada

- Migração para `dynamic-security` do Mosquitto ou plugins dedicados para revogação **online** sem interromper todos os clientes.
- Identidade atrelada a certificado individual (mTLS), com rotação e revogação de certificados.
- Limites por IP, controles anti-flood e observabilidade via systemd, métricas, dashboards e auditoria.
- Revisão dos privilégios da conta `bridge` e das operações de barramento local, que continuam privilegiadas.
- Execução isolada com contas systemd e teste de recuperação automatizado.

Fontes técnicas: https://mosquitto.org/man/mosquitto-conf-5.html; https://mosquitto.org/man/mosquitto_passwd-1.html; https://mosquitto.org/documentation/authentication-methods/ .
