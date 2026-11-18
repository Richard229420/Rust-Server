# Rust-Server — Fase 8.4.5.4-C

## Preparação segura para o corte, com cadastro de Client IDs e critérios de prontidão

**Situação:** implementada para execução de auditoria e planejamento no Arch Linux. **Não é autorização de corte.** Esta etapa NÃO migra o broker `8883`, não inicia `8884`, `8895` ou `8896`, não reinicia processos, não muda credenciais e não executa comandos de `mosquitto_ctrl`, `mosquitto_pub`, Git ou CI de escrita.

### Contexto e origem

As Fases 8.4.5.1–8.4.5.4-B foram validadas no Arch. O snapshot privado 8.4.5.2 contém 20 arquivos e a fase 8.4.5.4-B demonstrou equivalência de ACL para as identidades funcionais `lab`, `bridge`, `device-sensor02`, com senhas e Client IDs **temporários**. `device-sensor01` permanece revogado.

Antes de cortar, ainda precisamos verificar os Client IDs **de fato configurados** nos clientes da produção e o plano para troca/distribuição de credenciais e recuperação dos clientes. Os valores temporários `phase8454b-*` e `lab84-*` NÃO são evidência desses IDs reais.

### Entregáveis

- `scripts/fase8_4_5_4c_prontidao_corte.py`: `preflight`, `plano`, `modelo`, `avaliar`.
- `tests/test_fase8_4_5_4c_prontidao_corte.py`: 35 testes offline, sem segredos nem conexão a brokers.
- Este documento e um LEIA-ME resumido.

O script consulta a branch com `git branch --show-current` e exige `feature/fase8-4-inventory-dynsec`. Não faz `git checkout`, `add`, `commit`, `push` ou merge. Verifica o manifesto e integridade do snapshot usando as mesmas rotinas 8.4.5.2 e exige que os 20 arquivos de origem continuem iguais aos capturados (`assert_origins_match`). Usa a política legada validada pela 8.4.5.4-B. **Não afirma conhecer os Client IDs reais antes do inventário.**

### Antes de executar

1. Arch Linux, usuário normal (`sudo` e root proibidos).
2. Aplicar o patch SOMENTE em `~/server/services/multiprotocol`.
3. Manter o snapshot privado em `$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484` ou usar o identificador de snapshot efetivamente aprovado.
4. Não editar ou apagar tokens, certificados, `dynamic-security.json`, `devices.json` ou arquivos de configuração originais.
5. Os brokers 8883/8884 podem estar parados. Não é necessário iniciá-los.

### Instalação e testes (Terminal A)

```bash
cd ~/server/services/multiprotocol

git branch --show-current

unzip -o ~/Downloads/fase8-4-5-4c-preparacao-segura-corte-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .

python3 -B tests/test_fase8_4_5_4c_prontidao_corte.py
```

### Preflight somente leitura e plano

```bash
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"

python3 -B scripts/fase8_4_5_4c_prontidao_corte.py \
  preflight --snapshot "$SNAPSHOT"

python3 -B scripts/fase8_4_5_4c_prontidao_corte.py \
  plano --snapshot "$SNAPSHOT"
```

Se houver BLOQUEIO, não tente recrear snapshot ou aplicar chmod em arquivos de produção por tentativa. O script é fail-closed.

### Criar cadastro privado SEM senhas

**Uma única vez**, somente após preflight aprovado:

```bash
python3 -B scripts/fase8_4_5_4c_prontidao_corte.py \
  modelo --snapshot "$SNAPSHOT"
```

O arquivo criado será:

`~/.config/rust-server/phase8-4-5-4c/cadastro-prontidao.json`

Diretório `0700`, arquivo `0600`; não é escrito dentro do repositório Git nem em Downloads. O script NÃO imprime o conteúdo dos Client IDs ou caminhos de evidência. Não sobrescreve um cadastro existente. Não use `sudo`, nem compartilhe o cadastro com senhas ou prints de configuração privada.

**Editar manualmente** o arquivo com Neovim, depois de confirmar as identidades nos serviços e nos dispositivos reais:

```bash
nvim ~/.config/rust-server/phase8-4-5-4c/cadastro-prontidao.json
```

Campos por identidade:

- `username`: deve ser exatamente `lab`, `bridge` ou `device-sensor02`.
- `client_id`: Client ID **real, estável, distinto**, confirmado na configuração efetiva do cliente. Nunca um `phase8454b-*` ou `lab84-*` de ensaio. Se os clientes geram IDs aleatórios, NÃO marque como confirmado; será preciso planejar uma configuração de ID estável nos respectivos clientes.
- `evidence_kind`: uma entre `service-config`, `application-code`, `device-config`, `runtime-observation`.
- `evidence_ref`: identificador interno de evidência, entre 4 e 96 caracteres de `A-Z`, `a-z`, dígitos, ponto, hífen, sublinhado ou dois-pontos. **Não** é caminho de senha, chave, token ou conteúdo privado; exemplo fictício: `ticket-8454c-lab`.
- `client_id_confirmado`: verdadeiro somente após uma conferência real do cliente e de sua origem de configuração.
- `cliente_suporta_troca_credencial`: verdadeiro após documentar a forma segura de atualizá-lo.
- `retorno_credencial_legada_planejado`: verdadeiro quando houver procedimento e material autorizado para reverter o cliente à autenticação anterior.

Campos `readiness`, inicialmente todos `false`, exigem verificação manual **sem alterações em produção**: canal seguro de entrega das novas credenciais; procedimento de rotação; reconfiguração testada fora de produção; reconexão no rollback testada fora de produção; janela/responsáveis; monitoramento e gatilhos de aborto.

**Importante:** preencher `true` é uma declaração humana e **não** constitui prova técnica automática. Não coloque senhas, hashes, tokens ou chaves neste arquivo. Não use `chmod 644` para editar/compartilhar.

### Avaliar prontidão declarativa

```bash
python3 -B scripts/fase8_4_5_4c_prontidao_corte.py \
  avaliar --snapshot "$SNAPSHOT"
```

- Código de saída `0`: cadastro preenchido e estruturalmente validado, **apenas elegível para revisão manual**.
- Código de saída `3`: **PENDENTE** de informações/evidências. É esperado imediatamente após `modelo` e não significa erro de segurança.
- Código de saída `2`: **BLOQUEIO** de integridade, permissões, branch, snapshot ou estrutura do cadastro.

A saída nunca apresenta credenciais nem Client IDs. Mesmo com retorno `0`, o script termina informando **CORTE 8883 NÃO AUTORIZADO**.

### Estratégia para futura transição (não executada nesta fase)

1. Confirmar **IDs e configurações efetivas** dos clientes de `lab`, `bridge`, `device-sensor02`; garantir que IDs possam ficar estáveis. Atribuir um ID fixo no DynSec impediria a conexão de clientes que geram IDs aleatórios.
2. Gerar **novas credenciais individuais** em um cofre/gerenciador de segredos apropriado quando a janela for autorizada. Não reutilizar hashes ou senhas do `password_file` legado nem credenciais administrativas da fase 8.4.2. O cadastro desta etapa não guarda nem gera senhas.
3. Provisionar identidades no **futuro candidato de produção**, após autorização, com as ACLs e Client IDs documentados. Verificar DEFAULT DENY e `sensor01` desabilitado/ausente; evitar contas ou ACLs amplas.
4. Combinar previamente distribuição autenticada das credenciais novas e atualização dos clientes; a mudança para DynSec exige coordenar o momento de reconexão.
5. Guardar, com acesso restrito, **as credenciais legadas necessárias para rollback** até a janela de reversão ser formalmente encerrada. Um cliente migrado para senha nova terá de voltar à configuração/credencial antiga ao restaurar o broker legado.
6. Capturar snapshot final consistente sob manutenção, validar disponibilidade da equipe, executar CI e obter autorização explícita da auditoria de segurança antes do cutover.
7. No corte futuro, monitorar rejeições de conexão, assinaturas, publicação, latência e integridade dos alertas. Definir tempo de observação e critérios de rollback antes de iniciar. **Não realizar corte neste patch.**

### Critérios bloqueantes para corte 8.4.5.5

- Client IDs efetivos não conferidos em TODOS os clientes relevantes ou política de ID estável não aplicada.
- Credenciais novas e distribuição segura não planejadas / clientes indisponíveis para atualização.
- Plano de rollback sem retorno do **lado do cliente** às credenciais legadas; rollback apenas do broker não basta.
- Alterações desde o snapshot aprovado ou backup final não validado.
- Aprovação de Git/CI, revisão de segredos e decisão formal de Segurança ainda pendentes.

### Limite de segurança

Este módulo não lê nem exporta credenciais para inventário e não realiza consultas remotas. Ele **não comprova** Client IDs em uso sem a coleta manual de evidências, não valida distribuição real de credenciais, não mede corte e não exerce o rollback real de `8883`. O candidato 8.4.5.4-B permanece uma prova de equivalência de políticas, não um plano pronto para execução.

### Referências

- [Eclipse Mosquitto — Dynamic Security](https://mosquitto.org/documentation/dynamic-security/): Client ID opcional; para vinculação forte, username, senha e Client ID devem coincidir.
- [Eclipse Mosquitto — README Dynamic Security](https://github.com/eclipse-mosquitto/mosquitto/blob/master/plugins/dynamic-security/README.md): ações `setClientId`, `setClientPassword`, `disableClient`, `getClient`.
