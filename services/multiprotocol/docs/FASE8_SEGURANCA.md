# Fase 8 — segurança da mensageria (Arch Linux)

## Garantias implementadas neste pacote

1. **MQTT/TLS:** `rumqttd` apenas em `127.0.0.1:8883` usando rustls com certificado local; a porta MQTT 1883 não abre.
2. **MQTT CONNECT:** validação de credenciais em código com handler externo da versão `rumqttd 0.20`, com dois usuários fixos (`bridge`, `lab`). Conexões MQTT anônimas são recusadas. Senhas nunca ficam no TOML.
3. **Bridge MQTT:** `rumqttc` usa TLS, verifica o certificado do broker e autentica como usuário `bridge`; entrada apenas `lab/alerts`, `lab/sensors/*`, saída apenas `bus/alerts`, `bus/sensors/*`. Filas limitadas, QoS 0, sem entrega durável.
4. **TCP/TLS:** protocolo bus/1 em `127.0.0.1:7001` exige handshake TLS antes de qualquer frame. Usa rustls 0.23 e autenticação por token.
5. **Autorização TCP por função e tópico:** token admin (todas as ações e tópicos válidos), leitor (`SUB` em `alerts` ou `sensors/*`), publicador (`PUB` em `alerts` ou `sensors/*`). Tokens separados; permissão negada é auditada.
6. **Proteção operacional:** limite de 64 conexões TCP, deadline de autenticação de 5 s, máximo de 30 comandos/sessão/s, limites de frames, mensagens e filas.
7. **UDP legado:** **desabilitado por padrão**; ativar somente no loopback com `RUST_SERVER_ENABLE_LEGACY_UDP=1`, ciente de que o token trafega sem TLS e datagramas podem ser repetidos. Não recomendado.

### Limitação importante — ACL MQTT

O `rumqttd 0.20.0` suporta autenticação por conexão, mas **não há ACL nativa de PUB/SUB por tópico nesta implementação**. O filtro em `bridge.rs` **não impede** um cliente MQTT autenticado de publicar ou assinar tópicos diretamente no broker. Portanto, o usuário `lab` **não é uma credencial de produção com isolamento por tópico**. Mantenha o broker em loopback; nunca exponha :8883 diretamente a dispositivos não confiáveis. Para ACL MQTT de verdade, migre para um broker com autorização por tópico (ou implemente uma camada de autorização MQTT completa, separada e testada).

Os tokens `read` e `write` controlam apenas o protocolo TCP personalizado, **não o MQTT**. Autenticação forte com certificados de cliente (mTLS), limitação global de tentativas e controle de acesso por origem ainda não estão implementados.

## Instalação segura — preservar o HTTP original

No Arch Linux, o projeto original está em `~/server` e a Fase 7 em `~/server/services/multiprotocol`.

**Terminal A:** mantenha `cd ~/server && cargo run` (HTTP :8080).

**Terminal B:** pare o multiprotocolo anterior com Ctrl+C antes da atualização. Copie o patch após criar backup:

```bash
cd ~/server/services/multiprotocol
BACKUP="$HOME/Downloads/multiprotocol-fase7-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$BACKUP"
cp -a Cargo.toml README.md src examples configs docs scripts "$BACKUP"/
PATCH="$HOME/Downloads/fase8-seguranca-atualizacao"
diff -u Cargo.toml "$PATCH/Cargo.toml" || true
# Se nao houver edicoes locais suas que devam prevalecer:
cp -av "$PATCH/Cargo.toml" "$PATCH/README.md" ./
cp -av "$PATCH/src/"*.rs src/
cp -av "$PATCH/examples/"*.rs examples/
cp -av "$PATCH/configs/rumqttd.toml" configs/
cp -av "$PATCH/docs/FASE8_SEGURANCA.md" docs/
cp -av "$PATCH/scripts/"*.sh scripts/

bash scripts/setup_phase8.sh
source scripts/env_phase8.sh
cargo fmt           # formata os arquivos Rust da atualizacao
cargo fmt --check   # confirma a formatacao
cargo check
cargo test
cargo run
```

O setup **preserva todos os tokens existentes**. Se ainda nao existe uma CA local, copia o antigo certificado/chave `certs/localhost.*` para `certs/backup-*` e instala `certs/ca.crt`, `certs/ca.key` e um novo certificado de servidor `localhost.crt` (CA:FALSE) assinado pela CA. **A chave CA e privada; clientes devem receber somente `ca.crt`.** O novo certificado muda a identidade TLS confiavel, entao clientes antigos precisam passar a usar `ca.crt`. Nao use esta CA local como PKI de producao. Nao faca commit de tokens, `certs/*.key` ou `target`.

## Testes manuais

Em um terminal com `cd ~/server/services/multiprotocol && source scripts/env_phase8.sh`:

```bash
ss -lntup | rg ':(8080|8443|8883|7001|1883|7002)\b'
# MQTT :8883 e TCP :7001 somente em 127.0.0.1; :1883 e UDP :7002 ausentes
curl --cacert certs/ca.crt -i https://localhost:8443/
mosquitto_sub -h localhost -p 8883 --cafile certs/ca.crt \
  -u lab -P "$RUST_SERVER_MQTT_LAB_PASSWORD" -t bus/alerts -v
```

Em outro terminal com mesmo `cd` e `source`:

```bash
cargo run --example bus_client -- tcp-pub alerts "evento seguro"
mosquitto_pub -h localhost -p 8883 --cafile certs/ca.crt \
  -u lab -P "$RUST_SERVER_MQTT_LAB_PASSWORD" -t lab/alerts -m "MQTT seguro"
```

Para ver MQTT -> TCP-TLS, mantenha um assinante TCP em terceiro terminal:

```bash
cargo run --example bus_client -- tcp-sub alerts
```

Teste automatizado integrado (terminais A e B rodando):

```bash
source scripts/env_phase8.sh
bash scripts/test_phase8_security.sh
```

**Aviso:** `-P "$SENHA"` expõe a senha brevemente nos argumentos do processo de teste (`ps`); use somente neste laboratório local. Em implantação real prefira arquivo de configuração restrito ou API de cliente sem senha em argumentos. O `env_phase8.sh` carrega segredos na memória do processo e ambiente dos subprocessos; proteja o usuário Unix.

## Rollback

Pare somente o multiprotocolo; restaure `Cargo.toml`, `src/`, `examples/`, `configs/`, `docs/`, `scripts/`, `README.md` do backup criado antes da atualização. Não restaure nem sobrescreva `certs/` ou `~/.config/rust-server/` desnecessariamente. O backend HTTP original em `~/server` não é alterado.

## Próxima etapa antes de rede externa

Escolher broker MQTT com ACL real por tópico, credenciais por dispositivo e identidade, autenticação mTLS, rate limit por IP, logs estruturados e métricas. Para o protocolo UDP, implementar transporte seguro (ex. DTLS) ou substituir por MQTT/TCP-TLS.
