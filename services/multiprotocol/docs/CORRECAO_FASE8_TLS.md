# Correcao Fase 8 — certificado servidor, bridge, cliente e HTTP

## Causas identificadas a partir dos logs

- `E0609` em `examples/bus_client.rs`: `UdpSocket` nao possui campo `.sock`. Corrigido para `socket.set_read_timeout(...)`.
- `CaUsedAsEndEntity` na bridge TLS: certificado antigo tinha perfil de CA; um certificado com `CA:TRUE` nao deve ser usado como certificado final do servidor. Agora o script gera uma CA local (`ca.crt`, `ca.key`) e um certificado leaf (`localhost.crt`, `localhost.key`) com `CA:FALSE`, EKU `serverAuth` e SANs localhost/127.0.0.1.
- O gateway `502` e independente da TLS MQTT: backend HTTP na porta 8080 nao estava disponivel. Subir simultaneamente `cd ~/server && cargo run`.
- Falha no `mosquitto_pub`: repetir apos corrigir a cadeia TLS; se continuar, verificar stderr do broker e credenciais do usuario `lab`.

## Operacao segura no Arch Linux

Pare apenas o processo multiprotocolo. Faca backup do codigo, nao coloque chaves e senhas em Git.
O script preserva os segredos existentes. Ao migrar da versao sem CA, copia `certs/localhost.crt` e `.key` antigos para `certs/backup-*` e instala uma nova cadeia. A identidade TLS e alterada; clientes devem confiar no **novo** `certs/ca.crt`.

```bash
cd ~/server/services/multiprotocol
bash scripts/setup_phase8.sh
source scripts/env_phase8.sh
openssl verify -CAfile certs/ca.crt -purpose sslserver certs/localhost.crt
openssl x509 -in certs/localhost.crt -noout -text | rg -A 2 'Basic Constraints|Extended Key Usage|Subject Alternative Name'
cargo fmt && cargo fmt --check && cargo check && cargo test
cargo run
```

Em um terminal separado, mantenha o HTTP original rodando com `cd ~/server && cargo run`. Para testar:

```bash
curl --cacert certs/ca.crt -i https://localhost:8443/
mosquitto_pub -h localhost -p 8883 --cafile certs/ca.crt \
  -u lab -P "$RUST_SERVER_MQTT_LAB_PASSWORD" -t lab/alerts -m teste
bash scripts/test_phase8_security.sh
```

**Nao use** `-k`, `--insecure` ou desabilitacao de verificacao TLS para contornar falhas de certificado. Chave CA fica na maquina de laboratorio, nao deve ser distribuida.

**Escopo:** Corrige transporte/autenticacao de laboratorio; nao implementa ACL MQTT nativa por topico no rumqttd, mTLS ou persistencia garantida.
