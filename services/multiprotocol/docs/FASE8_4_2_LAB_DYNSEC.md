# Rust-Server — Fase 8.4.2: Mosquitto experimental com Dynamic Security

## Escopo

- **Único host:** Arch Linux (`~/server`). O Debian não participa.
- **Broker estável 8.3:** `127.0.0.1:8883`, permanece inalterado (password_file/ACL da fase anterior).
- **Broker laboratório 8.4.2:** `127.0.0.1:8884`, outra instância, arquivo de configuração e TLS próprios, Dynamic Security ativado somente neste processo.
- Não mexer em `data/`, `~/.config/rust-server/mosquitto/`, `services/multiprotocol/certs/`, `~/server_backups/`, serviços systemd ou arquivos do Debian.
- O estado inicial é `sensor01=revoked`, `sensor02=active` **no broker 8883**; nomes reutilizados na porta 8884 são **identidades fictícias independentes**. Sua senha e estado não são compartilhados.
- Não incluir arquivos de `~/.config/rust-server/phase8-4-2-lab/` em Git, tickets ou chat. Os arquivos `.opts` contêm **senhas de laboratório em texto puro** e estão limitados a 0600.

## Pré-requisitos

Arch Linux com Mosquitto 2.1.2, `mosquitto_ctrl`, `mosquitto_pub`, `mosquitto_sub`, OpenSSL e Python 3:

```sh
pacman -Q mosquitto openssl
ls -l /usr/lib/mosquitto_dynamic_security.so
ss -lntp | rg ':(8883|8884)\b' || true
```

Se `~/.config/rust-server` já existe, confirme que pertence ao usuário do Arch e tem permissões privadas:

```sh
stat -c '%a %U %n' ~/.config/rust-server
# Se pertencer a voce e estiver aberto a outros:
chmod 700 ~/.config/rust-server
```

## Preparação (Terminal D, somente uma vez)

```sh
cd ~/server/services/multiprotocol
python3 tests/test_fase8_4_2_lab.py
python3 scripts/fase8_4_2_lab.py preparar
```

A etapa `preparar`:

1. Recusa `sudo`, porta 8884 ocupada, plugin ausente, diretórios inseguros e laboratórios já existentes.
2. Cria `~/.config/rust-server/phase8-4-2-lab` (0700), com certificados e chave CA/servidor **novos** (sem copiar a PKI da 8.3).
3. Gera `mosquitto-lab.conf` com `listener 8884 127.0.0.1`, `listener_allow_anonymous false`, TLS e `plugin_load`/`plugin_use` da API 2.1.
4. Solicita senha administrativa forte (digitada sem eco). Passa a senha ao `mosquitto_ctrl dynsec init` via stdin, sem utilizá-la como argumento shell. **Guarde-a em um gerenciador de senhas**; o script não a armazena.
5. Não inicia o broker nem altera o 8883.

> Se a preparação for interrompida, não execute novamente sobre arquivos parciais. Inspecione apenas a pasta de laboratório e recrie com um novo diretório isolado depois de fazer backup da pasta parcial; **nunca exclua a pasta `mosquitto` antiga**.

## Iniciar broker de laboratório (Terminal E)

```sh
cd ~/server/services/multiprotocol
python3 scripts/fase8_4_2_lab.py iniciar
```

Esse processo fica no terminal e usa apenas a porta 8884. Finalize com `Ctrl+C`. Não inicie se a porta já estiver em uso.

## Provisionar laboratório (Terminal D)

Com Terminal E em execução:

```sh
cd ~/server/services/multiprotocol
python3 scripts/fase8_4_2_lab.py provisionar
```

Informe a senha administrativa definida em `preparar`. Uma configuração de controle temporária, privada, é criada e **apagada** ao sair do comando; senhas dos três clientes são aleatórias, transmitidas ao `mosquitto_ctrl` via **stdin**, não via lista de argumentos.

O provisionamento configura padrão `deny` para envio, recebimento, subscribe e unsubscribe, depois cria:

| Identidade exclusiva do laboratório | Client ID fixo | Publica | Assina / recebe |
| --- | --- | --- | --- |
| `device-sensor01` | `lab84-sensor01` | `lab/sensors/sensor01/#` | `bus/sensors/sensor01/#` |
| `device-sensor02` | `lab84-sensor02` | `lab/sensors/sensor02/#` | `bus/sensors/sensor02/#` |
| `lab84-bridge` | `lab84-bridge` | `bus/sensors/#` | `lab/sensors/#` |

O broker 8884 tem privilégios de administração isolados, exclusivos. `lab84-admin` não deve ser usado para publicar dados de sensores.

O provisionamento é **não idempotente** para evitar modificações acidentais: se interrompido no meio, não o repita cegamente. Será necessário inspecionar o inventário do laboratório antes da recuperação. Nenhuma alteração afeta 8883.

## Testar isolamentos reais (Terminal D)

```sh
cd ~/server/services/multiprotocol
python3 scripts/test_fase8_4_2_isolamento.py
python3 scripts/fase8_4_2_lab.py status
```

O teste executa seis verificações de plano de dados, incluindo entrega autorizada e ausência de entrega de tópicos cruzados. MQTT 3.1.1 pode permitir conexão com assinatura não autorizada e só impedir entrega; **não basta confiar somente no código de retorno da assinatura**. Testes com filtros não autorizados validam que os dados não foram recebidos. Não use `--insecure` ou listeners em `0.0.0.0`.

Confirme, no terminal do broker, o uso de `TLS` e eventos de `Denied PUBLISH` nas tentativas negativas. Não exiba senhas ou arquivos `.opts`.

## Segurança e limites da Fase 8.4.2

- A senha administrativa permanece conhecida pelo operador; perdê-la impedirá novas configurações via `mosquitto_ctrl` sem recuperação.
- A chave CA privada e senhas de laboratório existem apenas na pasta privada. Elas **não** fazem parte do snapshot da 8.4.1. Proteja-as com backups **criptografados** se forem necessárias após testes.
- Padrão `deny`; isolamento lógico depende das ACL e das validações de entrega.
- O plugin grava seu estado no JSON local. Não edite o JSON enquanto o broker estiver rodando.
- Limites de recuperação de operações multi-etapa: se cair durante o provisionamento, o broker 8884 pode conter estado parcial. Isso não autoriza migração ao 8883.
- Não exponha a LAN nem altere os bancos SQLite ou certificados existentes.
- A revogação **online** de clientes conectados ainda é tarefa da Fase **8.4.3**.

## Git

Somente scripts, testes e este Markdown podem ser versionados. NÃO usar `git add -A` ou `git add .` para incluir credenciais. Recomenda-se branch `feature/fase8-4-dynamic-security` após sincronizar com a conversa dedicada Git/GitHub.

## Referências (Mosquitto)

- https://mosquitto.org/documentation/dynamic-security/
- https://mosquitto.org/documentation/listeners/per-listener-settings/
- https://mosquitto.org/man/mosquitto_ctrl-1.html
- https://www.mosquitto.org/man/mosquitto_ctrl_dynsec-1.html
