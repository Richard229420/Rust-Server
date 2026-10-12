# Fase 4 — HTTPS/TLS e endurecimento HTTP

**Projeto:** Rust-Server (HTTP/1.1, TCP, 16 workers, fila de 128)

**Situação:** pacote de implementação incremental; requer validação de compilação e testes no Arch Linux do proprietário do projeto. O servidor é educacional, **não homologado para tráfego público ou dados sensíveis**.

## O que foi acrescentado

1. `src/security.rs`: valida *bytes originais* de requisições HTTP/1.1 antes de `Request::parse`. Recusa linha de requisição ambígua, headers com quebras de linha incorretas, `Host` ausente ou repetido, obs-fold, CTLs/obs-text, `Transfer-Encoding`, `Expect`, `Upgrade`, request-target diferente de origin-form e caminhos com travessia (`../`, codificação percentual e separadores codificados).
2. `src/server.rs`: incorpora a validação anterior mantendo os 16 workers e as métricas. Corrige a ausência de resposta 400 em falhas de `Request::content_length`, impede bytes excedentes já recebidos na mesma leitura (pipelining não suportado), adiciona cabeçalhos de proteção às respostas de sucesso e erro.
3. `observability/Caddyfile.local`: HTTPS TLS local em `https://localhost:8443`, com o Caddy fazendo proxy para `127.0.0.1:8080`, **bind apenas em loopback** e bloqueio de `/metrics` antes de encaminhar ao backend.
4. `tests/security_http.py`: 18 testes de integração adicionais, pela rede TCP real.
5. `tests/https_tls.py`: teste das rotas via HTTPS e da proteção do endpoint de métricas, com verificação de certificado por padrão.
6. `scripts/test_phase4.sh`: execução dos testes unitários, da Fase 3 com `--stress` e dos novos testes de segurança.

### O que NÃO está implementado

- TLS dentro do próprio processo Rust, mTLS e TLS entre Caddy e backend: aqui há **terminação TLS no Caddy**, usando loopback local para o tráfego interno.
- HTTP/2 nativo no servidor Rust, HTTP/3, chunked body, 100-continue, pipelining, WebSocket, keep-alive persistente.
- Conformidade total RFC 9112, fuzzing abrangente, autenticação, autorização, limitação de taxa por IP ou prevenção completa de request smuggling.
- Endpoint `/metrics` autenticado; ele é **local no backend** e bloqueado no proxy Caddy.

## Estrutura incremental

```text
server/
├── Cargo.toml                         (preservado)
├── Cargo.lock                         (preservado)
├── src/
│   ├── main.rs                        (preservado)
│   ├── server.rs                      (atualizado)
│   ├── metrics.rs                     (preservado)
│   ├── security.rs                    (novo)
│   ├── request.rs                     (preservado)
│   ├── response.rs                    (preservado)
│   └── ...                            (demais modulos preservados)
├── tests/
│   ├── integration_http.py            (preservado)
│   ├── load_test_16000.py             (preservado)
│   ├── security_http.py               (novo)
│   └── https_tls.py                   (novo)
├── scripts/
│   ├── test_phase3.sh                 (preservado)
│   └── test_phase4.sh                 (novo)
├── docs/
│   ├── FASE3.md                       (preservado)
│   └── FASE4.md                       (novo)
└── observability/
    ├── prometheus.yml                 (preservado)
    ├── Caddyfile.local                (novo)
    └── Caddyfile.production.example   (novo: exemplo apenas)
```

## Instalação

1. Mantenha o estado atual versionado (`git status` deve estar limpo), se possível, e crie uma branch: `git switch -c feature/https-security`.
2. Baixe para `~/Downloads/` os arquivos `rust_http_fase4_https_security.zip` e `instalar_fase4.sh`.
3. Execute `bash ~/Downloads/instalar_fase4.sh`. O instalador verifica os arquivos e gera backups em `~/server_backups/fase4_...`.
4. Confira `tree -a -I 'target|.git|__pycache__' -L 3`.

O instalador **não modifica** `main.rs`, `router.rs`, `request.rs`, `response.rs`, `metrics.rs`, `Cargo.toml`, `Cargo.lock`, README nem os testes da Fase 3.

## Validação HTTP/Rust (Caddy não necessário)

**Pare o servidor antigo na porta 8080**, porque os scripts de integração iniciam instâncias próprias.

```bash
cd ~/server
cargo fmt
cargo check
cargo test
cargo build --release
python3 tests/integration_http.py --stress
python3 tests/security_http.py
```

Ou simplesmente `bash scripts/test_phase4.sh` após `cargo fmt`.

Os 10 testes Rust da Fase 3 devem continuar aprovados, além dos testes unitários de `security.rs`. Os 17 testes de integração anteriores, incluindo sobrecarga, também devem continuar passando. Os 18 novos testes de segurança devem aprovar. Resultados são **esperados, não aferidos neste pacote**.

## HTTPS local com Caddy

Instale o Caddy no Arch:

```bash
sudo pacman -S caddy
```

**Terminal A:** inicie o Rust (sem outro servidor na porta 8080):

```bash
cd ~/server
cargo run --release
```

**Terminal B:** valide o Caddyfile e inicie o proxy no próprio usuário:

```bash
cd ~/server
caddy validate --config observability/Caddyfile.local --adapter caddyfile
caddy run --config observability/Caddyfile.local --adapter caddyfile
```

**Terminal C:** execute testes locais rápidos:

```bash
curl -k -i https://localhost:8443/health
curl -k -i https://localhost:8443/metrics  # deve ser 403
curl -k -I https://localhost:8443/        # HEAD pode ser 405 no backend
python3 tests/https_tls.py --insecure-local
```

`-k` e `--insecure-local` **DESATIVAM A VALIDAÇÃO DO CERTIFICADO**, e servem **somente para exercitar a criptografia no laboratório local**, não para comprovar confiança/autenticidade. A validação TLS completa requer confiar explicitamente na CA local do Caddy (por exemplo, `caddy trust`, conforme sua instalação), e então usar `curl -i https://localhost:8443/health` e `python3 tests/https_tls.py` sem opções inseguras. Não copie a CA privada nem chaves para o Git.

**Importante:** o servidor Rust continua em **HTTP na porta 8080**. HTTPS existe somente na porta **8443** atendida pelo Caddy. O Caddy deve permanecer em execução em outro terminal ou serviço. A configuração `Caddyfile.production.example` é apenas esboço; não a ative no estado atual do projeto.

## Por que `/metrics` precisa ser bloqueado no proxy?

O código Rust restringe `/metrics` ao loopback com `peer_addr()`. O Caddy se conecta ao backend a partir do loopback, portanto todas as requisições encaminhadas pelo Caddy parecem locais para o Rust. O proxy deve bloquear essa rota explicitamente antes do `reverse_proxy`.

## Segurança: limites importantes

- A validação é **intencionalmente estrita e incompleta**. Rejeitar obs-text, HTAB e certos request targets limita compatibilidade com alguns clientes/proxies; não é uma implementação HTTP universal.
- `Host` e caminhos HTTP são validados para reduzir ambiguidade e exposição. A normalização, a resolução de arquivos estáticos e a aplicação de ACLs devem ser revisadas em `router.rs` / `handlers.rs` antes de qualquer publicação externa.
- Não confiamos em `X-Forwarded-For` como identidade do cliente. A autenticação e autorização ainda não foram implementadas.
- `Content-Security-Policy` e `X-Frame-Options` são defesa em profundidade, não substitutos para escape de conteúdo e proteção de dados.
- Não utilizamos HSTS em `localhost`/HTTP backend; o exemplo de domínio público contém HSTS e requer uma revisão de segurança antes de uso.
- Os timeouts e limites permanecem em 5s, 15s e 8192 bytes; ainda cabe criar testes de capacidade, fuzzing e revisão formal de threat model.

## Voltar à Fase 3

Após instalar, o instalador imprime o caminho do backup. Pare o servidor, identifique o caminho real, e restaure o arquivo correspondente:

```bash
cd ~/server
cp ~/server_backups/fase4_YYYYMMDD_HHMMSS/server.rs src/server.rs
# Remover src/security.rs e demais novos arquivos apenas se desejar;
# sem mod security no server restaurado, security.rs nao sera compilado.
cargo fmt && cargo test && cargo build --release
```

Evite `git reset --hard` com alterações não commitadas. Se a Fase 3 tiver sido commitada e o diretório estiver limpo, a branch original também é opção de recuperação.

## Referências de projeto

- RFC 9112 — HTTP/1.1 e framing: https://www.rfc-editor.org/rfc/rfc9112.html
- Caddy HTTPS local: https://caddyserver.com/docs/quick-starts/caddyfile
- Caddy reverse proxy: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy
- Caddy bind: https://caddyserver.com/docs/caddyfile/directives/bind
