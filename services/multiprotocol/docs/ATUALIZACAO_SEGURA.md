# Atualizacao segura da Fase 6 para Fase 7

A versao Fase 7 nao substitui `~/server/src/`: a atualizacao e somente em
`~/server/services/multiprotocol`.

## Aplicar o patch (recomendado)

Pare o Terminal B com `Ctrl+C`, mas deixe o Terminal A com o HTTP original
em execucao. Os exemplos abaixo assumem o ZIP `fase7-bridge-atualizacao.zip`
descompactado em `~/Downloads`.

Antes de copiar os arquivos, crie um backup isolado, fora do projeto:

```bash
cd ~/server/services/multiprotocol
BACKUP="$HOME/Downloads/multiprotocol-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a Cargo.toml src configs README.md "$BACKUP"/

PATCH="$HOME/Downloads/fase7-bridge-atualizacao"
# Aplique apenas sobre o crate multiprotocolo, nao sobre ~/server/src.
cp -av "$PATCH/Cargo.toml" ./
cp -av "$PATCH/README.md" ./
cp -av "$PATCH/src/"*.rs ./src/
cp -av "$PATCH/configs/rumqttd.toml" ./configs/
mkdir -p docs scripts
cp -av "$PATCH/docs/"*.md ./docs/
cp -av "$PATCH/scripts/"*.sh ./scripts/

export RUST_SERVER_BUS_TOKEN="$(cat ~/.config/rust-server/bus.token)"
cargo fmt
cargo fmt --check
cargo check
cargo test
cargo run
```

Se o projeto ja contem alteracoes suas, use `diff -u` nos arquivos antes de
copiar. O patch foi baseado no ZIP do projeto aprovado na fase anterior.
`certs/`, `target/`, `Cargo.lock` e qualquer token local nao sao alterados.

## Validacao

Em outros terminais, use os testes de `FASE7_BRIDGE.md` ou
`bash scripts/test_phase7_bridge.sh`. Depois, verifique que HTTPS ainda
funciona e `/metrics` permanece bloqueado:

```bash
curl --cacert certs/localhost.crt https://localhost:8443/
curl --cacert certs/localhost.crt -i https://localhost:8443/metrics
```
