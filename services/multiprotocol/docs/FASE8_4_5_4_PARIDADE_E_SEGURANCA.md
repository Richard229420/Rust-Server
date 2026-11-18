# Rust-Server — Fase 8.4.5.4 — Paridade funcional e segurança

## Escopo e decisão

Auditar o **snapshot 8.4.5.2**, verificar politicas legadas versus DynSec em copias, validar certificados e ensaiar dados MQTT em brokers **temporários** `127.0.0.1:8895` e `127.0.0.1:8896`. Não altera `8883`, `8884`, `.opts`, contas, chaves, JSON DynSec em uso, banco SQLite, branch Git nem o snapshot. Não executa `mosquitto_ctrl` ou comandos mutantes. O script não substitui a auditoria Git/CI e a decisão do chat Chaves e Segurança.

**Dado importante:** o candidato 8895 é uma cópia do **laboratório** 8884, e *não* é uma migração da política legada 8883. Mesmo em caso de sucesso, o script informa `PARIDADE DE PRODUCAO PENDENTE` e `Corte 8883 NAO AUTORIZADO`. Os testes não são equivalentes a testes em produção ou prova de rollback real do 8883.

## Auditoria estática

- Confere manifesto SHA-256/permissões/snapshot 20/20, origens ainda compatíveis e listeners temporários disponíveis.
- Reconstrói o inventário e ACL legado (`lab`, `bridge`, `device-sensor02`), confirma `sensor01` revogado.
- Abre *somente a cópia privada* de `dynamic-security.json` em memória, compara `defaultACLAccess` DENY em quatro controles, clientes esperados, Client IDs, `disabled`, papéis e ACLs concedidas, e recusa identidades/grupos adicionais inesperados.
- Os objetos de controle do DynSec possuem papéis e grupos que podem herdar permissões; o teste bloqueia qualquer associação a grupo para os três dispositivos de laboratório.
- Confere certificados do **lab** e do **legado/candidato**: cadeia X.509 estrita (`openssl verify -x509_strict`), hostname `localhost`, expiração, SAN `DNS:localhost` e correspondência entre a chave pública do certificado e da chave privada. O arquivo PEM não é exibido. **Se o certificado legado falhar na validação estrita, não desabilite essa verificação nem troque a CA automaticamente.** Reconciliar certificados no chat Chaves e Segurança, atualizar backups controladamente e reauditar.

## Ensaio de dados MQTT

Ao executar `ensaiar`, com todos os pré-requisitos aprovados:

1. Copia os 20 arquivos para diretório temporário privado em `~/server_backups/fase8_4_5_2` e prepara configs 8895 e 8896, derivadas **somente da cópia**.
2. Inicia temporariamente o candidato DynSec **8895**. Prova `sensor02 -> bridge` em `lab/sensors/sensor02/telemetry`; prova `bridge -> sensor02` em `bus/sensors/sensor02/status`; confirma `sensor01` desabilitado e negação explícita de publicação cruzada de `sensor02` por **PUBACK MQTT 5 reason code 0x87**.
3. Encerra o candidato, inicia temporariamente o legado de rollback **8896**. Prova `lab -> bridge` no tópico `lab/alerts` e `bridge -> lab` em `bus/alerts`.
4. Encerra apenas os processos iniciados pelo ensaio, verifica snapshot e origens intactos, confirma que 8895/8896 foram liberadas e que o estado de 8883/8884 não mudou.

O ensaio não cria nem migra identidades reais. As credenciais residem em arquivos `.opts` temporários, nunca nos argumentos de `mosquitto_pub/sub` ou na saída do script. Uma saída negativa de rede, sozinha, **não** conta como ACL negada: a publicação cruzada exige PUBACK explícito `0x87`.

## Lacunas que impedem 8.4.5.5

- Contas `lab` e `bridge` (e seus Client IDs/ACLs de alertas) ausentes na configuração candidata de laboratório; `lab84-bridge` não é `bridge`.
- Senha e fluxo de provisionamento da identidade produtiva de `device-sensor02` ainda não migrados/validados na arquitetura candidata, embora o nome de usuário coincida.
- Necessária configuração candidata **específica de produção**, construída a partir do inventário legado e aprovada em segurança, sem reativar `sensor01`.
- Paridade com estado efetivo em memória do broker final só poderá ser confirmada na configuração candidata definitiva, em ensaio separado, sem importar JSON lab para produção.
- Auditoria Git/CI, autorização do corte e plano de manutenção/rollback real permanecem independentes.

## Arch Linux — instalação incremental (Terminal A)

Manter branch exata `feature/fase8-4-inventory-dynsec`:

```bash
cd ~/server/services/multiprotocol
git branch --show-current
unzip -o ~/Downloads/fase8-4-5-4-paridade-seguranca-arch.zip 'scripts/*' 'tests/*' 'docs/*' -d .
python3 -B tests/test_fase8_4_5_4_paridade.py
```

Usar **o snapshot já aprovado**, sem criar nem sobrescrever outro:

```bash
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
python3 -B scripts/fase8_4_5_4_paridade.py preflight --snapshot "$SNAPSHOT"
```

**Se** o preflight for aprovado:

```bash
python3 -B scripts/fase8_4_5_4_paridade.py ensaiar --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_2_preparar.py verificar --snapshot "$SNAPSHOT"
ss -lntp | rg ':(8883|8884|8895|8896)\b' || true
```

Brokers 8883/8884 podem permanecer parados; não é necessário abrir Terminais B/C. **Nenhum comando deve ser repetido automaticamente após `BLOQUEIO`**. Não compartilhar arquivos sensíveis, certificados privados, hashes, tokens, `dynamic-security.json`, `.opts` nem o snapshot. Compartilhar somente saídas de status sem segredos.

## Dependências e fontes técnicas

- Mosquitto 2.1 — `plugin_load` e `plugin_use` no listener: https://github.com/eclipse-mosquitto/mosquitto/blob/master/www/pages/documentation/listeners/per_listener_settings.md
- Dynamic Security — clients, groups, roles e default ACL: https://github.com/eclipse-mosquitto/mosquitto/blob/master/plugins/dynamic-security/README.md
- OpenSSL — `openssl verify` e `-x509_strict`: https://docs.openssl.org/master/man1/openssl-verification-options/
