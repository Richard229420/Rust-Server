# Rust-Server — Fase 8.4.5.4-C.1: correção da verificação de liberação da porta 8895

## Ocorrência observada no Arch Linux

Os testes da bridge Rust passaram: TLS/CONNACK, MQTT para Bus, Bus para MQTT, disable/enable com reconexão, rotação da senha temporária e reversão da senha temporária. No encerramento do teste, a rotina compartilhada `fase8_4_5_3_ensaio.broker` exigia que um novo `socket.bind()` pudesse reutilizar a porta 8895 em até 2 segundos. A mensagem foi `BLOQUEIO: processo de ensaio nao liberou a porta`. Posteriormente, `ss -lntp` não retornou listener em 8895, e o snapshot foi validado.

**Hipótese provável:** conexões encerradas em estado TCP TIME_WAIT impedem o bind imediato, embora o processo Mosquitto já tenha terminado. Sem captura dos estados TCP no instante da falha, não se pode afirmar a causa com certeza.

## Correção de escopo mínimo

- Atualiza somente `scripts/fase8_4_5_4c1_bridge_rust.py` e seus testes; não altera `fase8_4_5_3_ensaio.py`, `src/bridge.rs`, `src/config.rs`, `src/mqtt.rs`, Cargo.toml da aplicação, segredos ou certificados.
- Usa `broker_for_bridge()`, contexto privado da Fase C.1, exclusivamente na porta 8895.
- Só sinaliza o processo Mosquitto que o próprio script iniciou. Aguarda `wait()` para confirmar seu encerramento; se necessário, encerra esse filho com terminate/kill.
- Para verificar liberação operacional, consulta passivamente a saída de `ss -H -lnt` e exige **ausência de listener em 8895**, inclusive listeners IPv4/IPv6 ou wildcard. A consulta deve funcionar; falhas bloqueiam.
- Conserva `p3.available` como pré-requisito antes de iniciar o broker, impedindo sobrescrever um serviço preexistente; não utiliza o resultado de `bind()` como teste de liberação depois do encerramento.
- Preserva as verificações finais do snapshot e dos brokers originais 8883/8884.

## Aplicação no Arch (usuário normal)

```bash
cd ~/server/services/multiprotocol
unzip -o ~/Downloads/fase8-4-5-4c1-correcao-liberacao-8895-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .
python3 -B tests/test_fase8_4_5_4c1_bridge_rust.py
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
python3 -B scripts/fase8_4_5_4c1_bridge_rust.py preflight --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_4c1_bridge_rust.py ensaiar --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_2_preparar.py verificar --snapshot "$SNAPSHOT"
ss -lntp | rg ':(8883|8884|8895|8896)\b' || true
```

Se falhar no preflight, **não** executar `ensaiar`. Se falhar no `ensaiar`, registrar a mensagem de bloqueio, verificar os listeners passivamente e não repetir automaticamente. Não usar `sudo`, `killall`, `fuser -k`, `pkill`, nem manipular 8883/8884. Não enviar credenciais, opções privadas MQTT ou conteúdo do snapshot para revisão.

## Evidência de desenvolvimento

No ambiente de teste, **47/47** testes offline C.1 passaram, com casos para saída de `ss`, liberação do PID filho, bloqueio se houver listener residual e prevenção de uso da verificação compartilhada. Regressão offline da linha 8.4.5.1 até C.1: **193/193** testes aprovados como usuário não-root. A validação operacional com Mosquitto/Rust no Arch ainda depende do ensaio no computador do projeto.

## Limites

Ausência de listener + encerramento do PID de teste prova que não há broker do ensaio mantendo a escuta em 8895; isso não garante bind imediato de qualquer configuração TCP sem SO_REUSEADDR em presença de TIME_WAIT. Este patch **não** autoriza o corte 8883 e **não** resolve pendências de clientes reais, credenciais operacionais ou aprovações de Git/CI e Segurança.
