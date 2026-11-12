# Rust-Server — Fase 8.4.5.4-B

## Paridade de identidades e políticas de produção (ensaio sem corte)

**Objetivo:** reproduzir o **modelo de autorização legado** na porta local e descartável `127.0.0.1:8895`, sem alterar o broker principal `8883`, o laboratório `8884`, o snapshot aprovado ou a branch Git. **Não é migração de produção.**

### Pré-requisitos e evidências

- Arch Linux, Mosquitto 2.1.x, `mosquitto_ctrl`, `mosquitto_pub`, `mosquitto_sub` e OpenSSL.
- Subfases 8.4.5.1–8.4.5.4 aprovadas; snapshot 8.4.5.2 intacto e compatível com os arquivos atuais.
- Executar como usuário normal, nunca `sudo`/root.
- Manter a branch `feature/fase8-4-inventory-dynsec`. O patch não executa comandos Git.
- Nenhuma operação de `provisionar`, `preparar` do laboratório, cópia de banco de credenciais ou substituição do `mosquitto.conf` original.

### Escopo de paridade

| Identidade funcional legada | ACL de publicação | ACL de recebimento/assinatura | Cliente do ensaio |
| --- | --- | --- | --- |
| `lab` | `lab/alerts` | `bus/alerts` | `phase8454b-lab` |
| `bridge` | `bus/alerts`, `bus/sensors/#` | `lab/alerts`, `lab/sensors/#` | `phase8454b-bridge` |
| `device-sensor02` | `lab/sensors/sensor02/#` | `bus/sensors/sensor02/#` | `phase8454b-sensor02` |
| `device-sensor01` (revogado) | Nenhuma | Nenhuma | Não criado; tentativa de autenticação deve ser rejeitada |

Políticas de leitura geram dois ACLs DynSec: `subscribePattern` e `publishClientReceive`. Políticas de escrita geram `publishClientSend`. Os **quatro** padrões (`publishClientSend`, `publishClientReceive`, `subscribe`, `unsubscribe`) são ajustados para **deny**. Não são autorizadas ACLs `#` globais, grupos herdados ou contas laboratoriais adicionais nos papéis funcionais.

**Credenciais:** todas as contas são criadas no ensaio com *senhas novas e aleatórias*, exclusivamente no diretório temporário privado (`0700`, arquivos `0600`). Não são reutilizados os tokens de `lab`, `bridge`, senhas ou hashes do `password_file`. Não há impressão de segredo ou transmissão de senha nos argumentos do processo. Os nomes funcionais são iguais aos legados para comparação de ACL, mas **os Client IDs `phase8454b-*` são apenas de ensaio** e ainda não equivalem aos Client IDs de produção.

**Certificados:** usa cópias do certificado e da chave do servidor legado, previamente validados por X.509_STRICT; o CA é usado na validação TLS. Não emite nem troca certificados. Essa reutilização ocorre apenas no processo local descartável, não no broker `8883`.

### Instalação — Terminal A

```bash
cd ~/server/services/multiprotocol
unzip -o ~/Downloads/fase8-4-5-4b-paridade-producao-arch.zip 'scripts/*' 'tests/*' 'docs/*' -d .
git branch --show-current
python3 -B tests/test_fase8_4_5_4b_paridade_producao.py
```

### Preflight somente leitura

```bash
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
python3 -B scripts/fase8_4_5_4b_paridade_producao.py preflight --snapshot "$SNAPSHOT"
```

O preflight revalida o snapshot, sua correspondência com a origem, a política e o material TLS. Exige portas `8895` e `8896` livres. Não inicia brokers e não grava credenciais.

### Ensaio operacional

**Somente após preflight aprovado:**

```bash
python3 -B scripts/fase8_4_5_4b_paridade_producao.py ensaiar --snapshot "$SNAPSHOT"
```

O ensaio copia os 20 arquivos para um diretório privado temporário, gera um estado DynSec **novo**, inicia o Mosquitto **somente em 8895**, provisiona os três perfis, confere o estado persistido e testa:

- Alerta `lab → bridge` e retorno `bridge → lab`;
- Telemetria `sensor02 → bridge` e retorno `bridge → sensor02`;
- Autenticação negada para `sensor01` e para cliente com Client ID de outra conta;
- Negação **explícita** de publicação via MQTT 5 `PUBACK 0x87` e assinatura via `SUBACK 0x87`;
- Integridade do snapshot e dos arquivos originais, portas temporárias livres após encerramento.

Ao encerrar, o diretório temporário é eliminado após a parada do processo filho. **Não criar um backup novo da produção como efeito colateral.**

### Conferência final

```bash
python3 -B scripts/fase8_4_5_2_preparar.py verificar --snapshot "$SNAPSHOT"
ss -lntp | rg ':(8883|8884|8895|8896)\b' || true
```

### Limitações explícitas e gates para corte

1. **Não comprovado:** transferência/rotação dos segredos reais de produção, distribuição segura a todos os clientes e compatibilidade de Client IDs reais.
2. **Não comprovado:** migração em operação com clientes persistentes e sessão ativa; rollback real do `8883` continua intocado.
3. **Não autorizado:** alterar `8883`, criar contas reais ou habilitar o candidato em produção.
4. **Pendente:** revisão de Git/CI, auditoria geral de segurança, plano de migração autorizado e confirmação de continuidade de serviços externos.

Mesmo se o ensaio passar, o resultado autorizado é somente **PARIDADE DE POLÍTICAS ENSAIADA**, nunca paridade completa de credenciais ou aprovação de corte.

### Fontes

- Eclipse Mosquitto, *Dynamic Security Plugin*: https://mosquitto.org/documentation/dynamic-security/
- Eclipse Mosquitto, *Mosquitto 2.1 per-listener settings*: https://github.com/eclipse-mosquitto/mosquitto/blob/master/www/pages/documentation/listeners/per_listener_settings.md
