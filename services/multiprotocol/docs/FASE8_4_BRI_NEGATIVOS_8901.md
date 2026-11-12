# Rust-Server — BRI-LAB: testes negativos em 8901

## Propósito

Testes negativos de **MQTT v3.1.1 / TLS / ACL**, exclusivamente no broker Mosquitto descartável em `127.0.0.1:8901`:

- `auth_rejeitada`: senha errada para usuário `bridge` deve impedir CONNECT;
- `ca_nao_confiavel`: CA não confiável deve impedir a conexão TLS;
- `acl_subscribe_negada`: usuário `injector`, com permissão de publicação apenas em `lab/alerts`, não pode assinar `bus/#`; a resposta SUBACK precisa indicar falha.

Utiliza PKI, contas e ACL temporárias criadas pelo script positivo `scripts/testar_bridge_bri_8901.py`. **Não utiliza credenciais de operação**, nem altera `src/`, índices C.9/C.10, PKI v2 ou brokers 8883/8884. Não exige root. Todos os testes Rust são `#[ignore]` e rodados individualmente pelo controlador Python. A saída do Rust fica suprimida pelo controlador.

## Instalação

No diretório `~/server`, confira e extraia o ZIP com `unzip -t` e `unzip -n`. O pacote positivo BRI-LAB-8901 deve estar instalado antes do negativo.

## Execução

```sh
cd ~/server/services/multiprotocol
cargo test --offline --locked --test bridge_fase8_4_bri_negativos --no-run
python3 -B scripts/testar_bridge_bri_negativos_8901.py
```

### Limites

1. O primeiro ensaio positivo `bridge::start()` foi aprovado no Arch Linux; estes testes negativos usam o **cliente real `rumqttc`**, mas **não chamam `bridge::start()` diretamente**. Validam política de TLS/credenciais/ACL do broker efêmero, não o runtime do cenário A.
2. O controle ACL testa **SUBSCRIBE negado** e sua resposta SUBACK. **Não** testa publicação negada, nem rotação, reconexão ou rollback.
3. Os três cenários usam o mesmo broker temporário, sem alteração de senha ou cert durante o teste. A porta 8901 deve estar livre. O broker é encerrado e o diretório temporário removido em saídas normais e erros tratados. SIGKILL/falha do host podem deixar resíduos privados que exigem verificação local.
4. Se um teste for BLOQUEADO, não substitua ou force asserções; revise a falha localmente antes de compartilhar qualquer saída. Sem baixa C-V1. **Não registre evidência do cenário B como evidência do cenário A na C.10.**
5. Testes de ambiente foram escritos e verificados sintaticamente no gerador; **a execução end-to-end precisa ser feita no Arch Linux, onde há Mosquitto e Cargo instalados**.
