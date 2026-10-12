# Rust-Server — Fase 4

Implementação incremental de **HTTPS local via Caddy** e **hardening HTTP/1.1 em Rust**, preservando as três fases anteriores. O objetivo é permitir testes seguros em *localhost* e ampliar a cobertura de erros no protocolo.

## Novos arquivos

| Caminho | Ação |
|---|---|
| `src/server.rs` | **Substituir** a versão da Fase 3; o instalador fará backup |
| `src/security.rs` | **Adicionar** parser preventivo e testes unitários |
| `tests/security_http.py` | Adicionar 18 testes HTTP negativos/positivos |
| `tests/https_tls.py` | Adicionar validação HTTPS com Caddy |
| `scripts/test_phase4.sh` | Adicionar validador da Fase 4 |
| `observability/Caddyfile.local` | HTTPS para localhost:8443 |
| `observability/Caddyfile.production.example` | Apenas referência, **não usar em produção** |
| `docs/FASE4.md` | Manual completo |

**Não substituir:** `main.rs`, `config.rs`, `router.rs`, `request.rs`, `response.rs`, `metrics.rs`, `Cargo.toml`, `Cargo.lock` ou arquivos da Fase 3.

## Aplicação e testes

```bash
cd ~/Downloads
bash instalar_fase4.sh
cd ~/server
cargo fmt && cargo check && cargo test && cargo build --release
python3 tests/integration_http.py --stress
python3 tests/security_http.py
```

Instale e execute Caddy apenas após validar o código Rust. Veja o passo a passo completo em `docs/FASE4.md`.

> **Status de entrega:** os scripts Python e shell foram validados sintaticamente e o instalador foi testado em uma estrutura simulada. A compilação Rust e os testes de rede necessitam execução no seu Arch Linux. O HTTPS criado aqui é de **terminação TLS no Caddy**, não TLS nativo em Rust.
