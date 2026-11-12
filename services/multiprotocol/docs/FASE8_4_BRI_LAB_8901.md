# Rust-Server — Ensaio isolado da bridge em 8901 (BRI-lab)

## Escopo

- Testa a funcao `bridge::start()` do arquivo original `src/bridge.rs` em um *broker efemero* Mosquitto `127.0.0.1:8901`.
- Usa `messaging::Bus` **adaptador de teste**, e nao a implementacao real de `src/messaging.rs`.
- A PKI, senhas e ACLs de laboratorio sao geradas em diretorio temporario privado (`0700`), removido ao final; sem qualquer credencial operacional.
- Nao toca nos brokers 8883/8884, na PKI v2, em arquivos de configuracao operacionais nem nos indices C.9/C.10.
- O teste Rust e marcado com `#[ignore]`, de modo que `cargo test` normal nao conecta a broker externo.
- Nenhuma evidencia BRI-01 do cenario A e fornecida por este ensaio.

## Instalacao

No diretorio `~/server`, primeiro faca `unzip -t` e depois `unzip -n` do arquivo ZIP. Confirme o diff e execute:

```sh
cd ~/server/services/multiprotocol
python3 -B scripts/testar_bridge_bri_8901.py
```

## Precondicoes

`cargo`, `mosquitto`, `mosquitto_passwd`, `openssl`, dependencias Cargo offline presentes e porta 8901 livre. Exige que a versao do codigo Rust continue compativel com o adaptador de teste. Executar sem `sudo`.

## Limites de garantia

O teste positivo comprova que a funcao real consegue estabelecer TLS/autenticacao/assinatura e que uma publicacao autorizada `lab/alerts` atravessa o caminho de entrada ate um bus de teste. Nao testa `SubAck` explicitamente, ACL negada, reautenticacao, rotacao, rollback, cliente sensor real, caminho bus/1 real ou release operacional. Resultados aprovados **nao** encerram BRI-01/02/03 nem qualquer das 21 pendencias C-V1.

O controlador suprime logs brutos para evitar vazamento acidental; problemas sao reportados de forma generica. Uma falha de compatibilidade pode exigir revisao local do teste. O diretorio de ensaio e apagado em saida normal/erro, inclusive se o teste Rust falhar; encerramento abrupto por `SIGKILL` ou queda do host podem deixar artefatos que devem ser inspecionados localmente.
