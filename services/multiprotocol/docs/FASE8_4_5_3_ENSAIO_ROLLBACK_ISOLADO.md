# Rust-Server — Fase 8.4.5.3: ensaio isolado de migração e rollback

## Escopo

Executa **somente** dois processos Mosquitto temporários, **em sequência**, sem alterar 8883/8884, a branch Git ou os arquivos do snapshot 8.4.5.2:

- `127.0.0.1:8895` — candidato **experimental** com cópia do Dynamic Security do **lab 8884** (sensor01 desabilitado; sensor02 e bridge ativos). **Não é migração de contas do 8883.**
- `127.0.0.1:8896` — recuperação **experimental** da configuração legada (password_file/acl_file, tokens `lab`/`bridge`) a partir do mesmo snapshot. **Não troca nem restaura o 8883 real.**

O script cria uma pasta temporária privada `0700` em `~/server_backups/fase8_4_5_2`, copia as 20 entradas do snapshot com arquivos `0600`, confere os hashes das cópias e reconstrói ambas as configurações com caminhos temporários absolutos. Nenhum processo aponta para `candidate/dynamic-security.json` do snapshot original, que é mantido imutável. A configuração original do 8883 e o laboratório 8884 não são editados. Os dados de senhas ficam em `.opts` privados e **não entram na linha de comando**.

**Critério de validade:** o snapshot ainda deve corresponder aos 20 arquivos de origem no início e no fim do ensaio. Se qualquer arquivo mudar, a operação é bloqueada; não reaproveite evidência desatualizada.

## Pré-requisitos

- Arch Linux, Mosquitto 2.1.x (o usuário confirmou 2.1.2), `mosquitto_pub`, `mosquitto_sub`, `ss`, Python 3.14; usuário normal, **sem sudo**.
- Subfases 8.4.5.1 e 8.4.5.2 aprovadas; arquivo snapshot 8.4.5.2 íntegro, com as 20 entradas preservadas e diretórios privados.
- Estado da 8.4.4 concluído antes do snapshot (sensor01 desabilitado só no lab 8884).
- Portas 8895 e 8896 livres. Brokers 8883 e 8884 podem estar ativos ou parados; a consulta a essas portas é passiva.
- Manter a branch existente `feature/fase8-4-inventory-dynsec` (nome exato dos logs). Este pacote não altera Git nem faz commit/push/merge.

## Instalação incremental — Terminal A

```bash
cd ~/server/services/multiprotocol

git branch --show-current

unzip -o ~/Downloads/fase8-4-5-3-ensaio-rollback-isolado-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .
```

## Verificação offline (não inicia brokers)

```bash
python3 -B tests/test_fase8_4_5_3_ensaio.py
```

A suíte local de desenvolvimento tem 24 testes sintéticos e mocks. **Esses testes não substituem a execução real do ensaio no Arch.**

## Preflight e simulação real no Arch

Usar **o caminho exato** do snapshot 8.4.5.2 aprovado:

```bash
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"

python3 -B scripts/fase8_4_5_3_ensaio.py preflight --snapshot "$SNAPSHOT"
```

Se aprovado (e apenas nesse caso):

```bash
python3 -B scripts/fase8_4_5_3_ensaio.py simular --snapshot "$SNAPSHOT"
```

O fluxo `simular` inicia o candidato em 8895, prova MQTT TLS com mensagem QoS1 `device-sensor02 -> lab84-bridge` e testa a recusa de `device-sensor01`. Em seguida encerra **somente o processo candidato criado pelo ensaio**, verifica que liberou a porta e inicia **outro processo** na porta 8896 com `password_file` e ACL legados restaurados em cópias. Confirma autenticação MQTT e entrega `lab -> bridge` em `lab/alerts`, encerra o processo de rollback e confere novamente integridade do snapshot e os listeners originais.

**Interpretação de sucesso:** a restauração legada é **funcional em ambiente de testes** e a migração candidata é **funcional para as identidades de laboratório**. Ainda não foi realizada recuperação real do 8883, nem paridade completa de identidade/autorização: ambas continuam dependentes de auditoria e autorização próprias.

## Pós-verificação

```bash
python3 -B scripts/fase8_4_5_2_preparar.py verificar --snapshot "$SNAPSHOT"
ss -lntp | rg ':(8883|8884|8895|8896)\b' || true
```

Deve **não haver** listeners em 8895/8896 após saída normal do script. As portas 8883/8884 devem conservar o estado de antes. Se houver qualquer `BLOQUEIO`, **não execute novamente automaticamente**. Não copie o snapshot nem envie seus arquivos, JSON, hashes, `.opts`, tokens ou certificados privados para o chat.

Se o Python for interrompido com SIGKILL ou o computador desligar, a limpeza automática pode não rodar. Nesse caso, verifique `ss -lntp` e identifique o processo antes de qualquer ação; não use `killall mosquitto` e não remova pastas privadas por tentativa. Faça a análise no chat de desenvolvimento.

## Limitações e próximos aceites

- Como o Dynamic Security 2.1 mantém o estado em memória e pode atualizar seu JSON, **não restaure o JSON sobre um broker ativo**. O ensaio só manipula cópias e processos efêmeros próprios.
- A credencial do `sensor02` e da bridge usadas em 8895 são do laboratório. Elas não são identidades migradas para 8883.
- A recuperação na porta 8896 é prova controlada da compatibilidade de autenticação e ACL do legado com os arquivos recuperados, não um exercício de troca de porta real.
- Segurança de certificados (SAN, validade, cadeia, crypto), igualdade exata das ACLs/papéis e teste completo do broker original são escopo 8.4.5.4. Testes Git/CI e autorização formal de corte são separados.
- **Corte para 8883 permanece NÃO AUTORIZADO até 8.4.5.5**, após aprovação do rollback, paridade, auditoria de segurança e controle de versão.

## Referências

- Mosquitto 2.1 — listener-scoped plugins: https://github.com/eclipse-mosquitto/mosquitto/blob/master/www/pages/documentation/listeners/per_listener_settings.md
- Mosquitto Dynamic Security: https://mosquitto.org/documentation/dynamic-security/
- Mosquitto 2.1 — opções `-o` em mosquitto_pub/sub: https://mosquitto.org/man/mosquitto_pub-1.html
