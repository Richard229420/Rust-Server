# Rust-Server Multiprotocolo — Fase 8 (segurança)

Gateway HTTPS sobre HTTP original, broker MQTT com TLS e autenticação, bridge MQTT ↔ TCP com TLS e papéis de leitura/publicação.

## Guia de instalação

Leia **[`docs/FASE8_SEGURANCA.md`](docs/FASE8_SEGURANCA.md)** antes de atualizar. Esta fase não altera `~/server/src/`; apenas `~/server/services/multiprotocol`.

**Mudanças incompatíveis com a Fase 7:** MQTT 1883 plaintext é substituído por MQTT TLS em 8883, TCP :7001 exige TLS (clientes anteriores não conectam), UDP :7002 vem desativado. Exemplos de clientes e scripts já foram atualizados.

```bash
cd ~/server/services/multiprotocol
bash scripts/setup_phase8.sh
source scripts/env_phase8.sh
cargo fmt
cargo fmt --check
cargo check
cargo test
cargo run
```

TLS e login MQTT não implicam ACL por tópico no broker: veja a limitação de segurança no guia. **Não expor fora do loopback.**
