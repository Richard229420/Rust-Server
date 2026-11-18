# Fase 8.4.5.4-C.1 — Correção da compilação do probe (rustls/ring)

## Causa

O Cargo.toml gerado para o probe temporário ativava `rumqttc/use-rustls`, mas não habilitava
`rustls/ring`. A implementação existente da bridge Rust seleciona explicitamente
`rumqttc::tokio_rustls::rustls::crypto::ring::default_provider()`, portanto a compilação
falhava com `error[E0433]: cannot find ring in crypto`.

## Correção

Adicionada dependência de `rustls` 0.23 com `default-features = false` e `features = ["ring"]`
ao Cargo.toml temporário do probe. Incluído teste de regressão que examina o manifesto
gerado sem executar o Cargo.

Esta correção NÃO altera o Cargo.toml do projeto, `src/bridge.rs`, `src/config.rs`,
`src/mqtt.rs`, o broker 8883/8884 ou qualquer credencial.

## Procedimento

Instalar o patch a partir da raiz `~/server/services/multiprotocol`:

```bash
unzip -o ~/Downloads/fase8-4-5-4c1-correcao-ring-arch.zip 'scripts/*' 'tests/*' 'docs/*' -d .
python3 -B tests/test_fase8_4_5_4c1_bridge_rust.py
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
python3 -B scripts/fase8_4_5_4c1_bridge_rust.py preflight --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_4c1_bridge_rust.py ensaiar --snapshot "$SNAPSHOT"
```

Se o ensaio bloquear, não execute novamente automaticamente: colete apenas um diagnóstico
sem segredos e preserve o snapshot. A correção resolve o erro específico de feature,
mas não comprova de antemão todo o ensaio operacional.
