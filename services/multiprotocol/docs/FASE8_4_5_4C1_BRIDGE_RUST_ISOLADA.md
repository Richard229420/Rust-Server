# Rust-Server — Fase 8.4.5.4-C.1: bridge Rust em ensaio isolado

## Escopo e limites

Este pacote **não altera** `src/main.rs`, `src/config.rs`, `src/mqtt.rs`, `src/bridge.rs`, os brokers `127.0.0.1:8883`/`:8884`, o snapshot original, o cadastro da C, a branch ou os arquivos de credenciais existentes. Não autoriza o cutover 8.4.5.5.

A implementação `src/bridge.rs` é **copiada** (somente leitura da origem) e compilada com Cargo em uma pasta `0700` descartável **fora do repositório**. O pequeno `fase8_4_5_4c1_bridge_probe.rs` usa um *observador de Bus* compatível com as chamadas da bridge para verificar entrada e saída. **Não testa o Bus/TCP-TLS de produção completo**, nem o processo principal. No código normal, `config.rs` e `mqtt.rs` continuam exigindo `127.0.0.1:8883`. O cliente MQTT do ensaio é a implementação Rust real da bridge.

Broker DynSec descartável: `127.0.0.1:8895`, TLS com CA e par certificado/chave **copiados do snapshot** em scratch. A CA é usada somente em arquivo privado temporário, sem divulgação de material privado. O candidato usa ACLs equivalentes às do inventário legado, identidades `lab`, `bridge`, `device-sensor02`, **senhas NOVAS temporárias** e **DEFAULT DENY**; `device-sensor01` não é provisionado. No ensaio a conta `bridge` é vinculada a `rust-server-bridge-local`; as demais identidades usam IDs exclusivos de teste, NÃO de produção.

## Procedimento no Arch Linux — Terminal A

Partindo de `~/server/services/multiprotocol` na branch `feature/fase8-4-inventory-dynsec`, extraia o pacote (somente `scripts/*`, `tests/*`, `docs/*`). Não copie arquivos do pacote para `$HOME/.config/rust-server`.

```bash
cd ~/server/services/multiprotocol
unzip -o ~/Downloads/fase8-4-5-4c1-bridge-rust-isolada-arch.zip 'scripts/*' 'tests/*' 'docs/*' -d .

python3 -B tests/test_fase8_4_5_4c1_bridge_rust.py

SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
python3 -B scripts/fase8_4_5_4c1_bridge_rust.py preflight --snapshot "$SNAPSHOT"
```

**Somente após preflight aprovado**, execute o ensaio operacional. Ele inicia **sozinho** o broker de teste `8895` e o executável Rust temporário, e os encerra ao final. Não inicie `8883`, `8884` nem outros terminais, e não use sudo.

```bash
python3 -B scripts/fase8_4_5_4c1_bridge_rust.py ensaiar --snapshot "$SNAPSHOT"
```

A compilação ocorre com `cargo build --offline --quiet` e `CARGO_TARGET_DIR` sob scratch; **não baixa dependências**, não modifica o `Cargo.lock` original nem os fontes originais. Se faltarem crates no cache do Arch, o ensaio **bloqueia**; revise o cache local e a política de dependências em Git/CI, **não altere as restrições 8883 nem force o teste**. Para diagnóstico somente local, compile em ambiente revisado sem compartilhar mensagens que contenham caminhos privados; a implementação deliberadamente suprime stderr de compilação no resumo operacional.

### O que é exercitado

1. Política DynSec equivalente ao legado (ACLs exatas, papéis, DEFAULT DENY; sensor01 excluído).
2. Client ID efetivo `rust-server-bridge-local`, usuário MQTT `bridge` e TLS com CA de teste.
3. MQTT `lab/alerts` → `bridge.rs` → chamada de entrega ao observador de Bus, com payload identificado.
4. Comando do observador de Bus → `bridge.rs` → MQTT `bus/alerts`, recebimento por `lab`.
5. `disableClient`/`enableClient` da conta bridge **somente no candidato**: exige segundo evento de conexão real do Rust e entrega bidirecional após reconexão, sem reiniciar o probe.
6. Com o probe parado, `setClientPassword` para **nova senha temporária**, negação explícita da antiga, reinicialização do probe com a nova e nova entrega bidirecional.
7. Com o probe parado, retorno à senha temporária anterior, negação da senha intermediária e entrega bidirecional pós-retorno.
8. Verificação final da integridade do snapshot, origens, estado dos listeners reais e liberação de `8895`/`8896`.

Nenhum token real é passado em argumentos de processo; as senhas de teste são geradas em scratch e disponibilizadas ao probe por arquivo 0600. O ambiente dos processos Rust é restrito para não transmitir tokens de shell ou variáveis `RUST_SERVER_*`. Logs do broker são suprimidos e o roteiro não exibe senhas. Não armazene credenciais de teste nem publique a saída do cadastro privado.

## Verificação posterior

```bash
python3 -B scripts/fase8_4_5_2_preparar.py verificar --snapshot "$SNAPSHOT"
ss -lntp | rg ':(8883|8884|8895|8896)\b' || true
```

Se os brokers originais já estavam parados, não haverá linhas. Se estavam ligados, devem conservar o mesmo estado, sempre vinculados a loopback.

### Não confundir evidência com autorização

- Um sucesso na **C.1** confirma a conexão e o fluxo da **implementação `bridge.rs`** contra DynSec `8895`, incluindo reconexão do cliente de teste. **Não comprova** a porta `8883`, o rollback real, o código inteiro do Bus, a operação de dispositivos externos, os Client IDs efetivos de `lab` e `device-sensor02` nem o provisionamento de credenciais de produção.
- O cadastro da Fase 8.4.5.4-C continua intocado. Não mude `client_id_confirmado` ou aprovações apenas porque este ensaio passou. A execução real da bridge na implantação ainda requer prova independente.
- Para qualquer `BLOQUEIO`, **não repita `ensaiar` automaticamente**. Verifique no seu terminal a mensagem resumida e as portas de teste; não altere manualmente arquivos do snapshot.
- Git/CI, auditoria de Segurança, janela, último backup consistente e rollback completo de broker **e clientes** são requisitos externos antes de 8.4.5.5.

## Arquivos incluídos

- `scripts/fase8_4_5_4c1_bridge_rust.py` — preparação, compilação privada, broker de ensaio, controle de rotação e validação.
- `scripts/fase8_4_5_4c1_bridge_probe.rs` — observador de Bus apenas para testes, **nunca carregar no binário de produção**.
- `tests/test_fase8_4_5_4c1_bridge_rust.py` — testes unitários offline, inclusive falha fechada em políticas e arquivos inseguros.
- `docs/FASE8_4_5_4C1_BRIDGE_RUST_ISOLADA.md` — este documento.
