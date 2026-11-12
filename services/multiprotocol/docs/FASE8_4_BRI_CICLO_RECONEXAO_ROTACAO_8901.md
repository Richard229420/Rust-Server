# Rust-Server Fase 8.4 — BRI ciclo TLS (8901): reconexao, rotacao e rollback

## Escopo

Ensaio **somente no cenario B**. O controlador `scripts/testar_bridge_bri_ciclo_8901.py` cria e encerra um Mosquitto TLS privado em **127.0.0.1:8901**, com CA, certificados e senhas gerados no momento, nunca usando a PKI real ou credenciais do projeto. O arquivo `tests/bridge_fase8_4_bri_ciclo.rs` importa diretamente `src/bridge.rs`, mas usa um adaptador do barramento interno; portanto, **nao valida o `messaging::Bus` real**. O teste Rust esta marcado `#[ignore]` e nao executa em `cargo test` normal.

Sem acesso remoto, sem `sudo`, sem alteracoes em `src/`, nos brokers **8883/8884**, indices C.9/C.10 ou credenciais existentes. O teste cria os arquivos sob tempdir privada (0700) e arquivos de senha (0600). Credenciais passam por arquivos de curta duracao, nao por argumentos `-P` do shell. Os processos iniciados pelo controlador sao encerrados em `finally` e a tempdir e removida.

## Sequencia testada

1. Conectar `bridge::start()` com senha **A**, publicar `lab/alerts` como `injector` e registrar passagem ao bus simulado.
2. Encerrar/reiniciar **apenas** o broker de teste, preservando **a mesma instancia** de bridge; comprovar nova entrega.
3. Encerrar o broker, trocar somente seu arquivo de senhas de **A** para **B** e reiniciar o broker de teste. Confirmar A rejeitada e B aceita por probes isolados. Conferir ausencia de entrega a bridge antiga ainda com senha A (complementar, janela limitada).
4. Encerrar a instancia antiga de bridge, criar **nova instancia** com senha B e comprovar entrega.
5. Encerrar bridge/broker, restaurar senha **A** no broker de teste, recusar B/aceitar A e comprovar entrega com **nova instancia** de bridge.

**Importante:** `bridge::start()` captura a senha na inicializacao. O teste nao comprova recarga de credenciais sem reiniciar o cliente; na rotacao e rollback reinicia somente o processo de teste da bridge. O proprio `src/config.rs` continua restringindo a aplicacao completa a 127.0.0.1:8883, e nao e modificado.

## Uso

No diretorio `~/server/services/multiprotocol`:

```sh
python3 -B tests/test_bri_ciclo_controlador.py
cargo test --offline --locked --test bridge_fase8_4_bri_ciclo --no-run
python3 -B scripts/testar_bridge_bri_ciclo_8901.py
```

O controlador compila o teste com `--offline --locked` e o executa diretamente. Nao execute o teste Rust ignorado isoladamente; isso pode iniciar uma conexao sem que exista o broker efemero preparado pelo controlador. O teste usa um prazo limitado e aborta em erro, nunca modificando autorizacoes existentes.

Se a execucao falhar, o controlador escreve `BLOQUEADO` e elimina os logs efemeros com o encerramento do contexto temporario. Para depuracao futura, apenas registrar o nome da fase e tipo de falha; nao publicar segredos, chaves ou logs brutos sem revisao de seguranca.

## Limites de evidencia

Nao demonstra implantacao operacional no cenario A, real `Bus`, alteracao de credenciais em runtime sem reinicializacao, entrega QoS1 da bridge, nem requisitos de aprovacao independente. A entrega `lab/alerts` e um ensaio de MQTT→bridge→bus adaptado. Nao promover a C-V1 como concluida, nao executar corte 8883, nao reativar `device-sensor01`.

**Status operacional permanece: 21 pendencias C-V1 abertas; C.9/C.10 imutaveis.**
