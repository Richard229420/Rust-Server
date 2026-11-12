# Rust-Server — Fase 8.4.5.4-C.5

## Avaliação operacional passiva e plano de evidências A/B

**Estado:** código implementado e testes **offline** aprovados no ambiente de preparação. A instalação/validação no Arch do usuário depende primeiro da C.4. Não é migração, simulação MQTT nem teste de clientes reais. **Não autoriza `8883`.**

### Sequência do projeto

- **8.4.5.4-C.1:** bridge Rust testada em Mosquitto temporário; homologação, não produção.
- **8.4.5.4-C.2:** clientes simulados, ACL e rotação/reconexão em laboratório; não prova implantação real.
- **8.4.5.4-C.3:** evidência estática da bridge registrada; cadastro C-v1 com 21 pendências no último resultado apresentado.
- **8.4.5.4-C.4:** classifica *cenário A* (operacional principal) e *cenário B* (laboratório secundário) em arquivo C-v2 privado. O usuário ainda não apresentou resultado de validação local dessa etapa.
- **8.4.5.4-C.5 (esta entrega):** avalia, **somente em leitura**, os dois cadastros, requisitos pendentes e plano de evidências por cliente. Não reduz as pendências automaticamente.
- **8.4.5.5 (corte real):** **BLOQUEADO** até decisões independentes de Segurança, Git/CI e prontidão operacional real.

### Arquivos

- `scripts/fase8_4_5_4c5_avaliacao_operacional.py` — ações `preflight`, `situacao` e `plano`, todas somente leitura;
- `tests/test_fase8_4_5_4c5_avaliacao_operacional.py` — 39 testes offline sem broker;
- `docs/FASE8_4_5_4C5_AVALIACAO_OPERACIONAL_A_B_SEM_CORTE.md` — este documento;
- `LEIA-ME-8454C5.txt` — sequência de aplicação no Arch.

O script C.5 depende de todos os scripts já instalados nas fases anteriores. Não modifica `src/`, scripts antigos, política do broker, ACL, certificados, banco SQLite, snapshots, Git ou arquivos privados C-v1/C-v2.

### Pré-requisito obrigatório: validar C.4 no Arch

O usuário já baixou o pacote C.4, mas **não forneceu ainda a saída de testes, preflight, criar e matriz**. Não é correto considerar C.4 aplicada sem verificá-la.

```bash
cd ~/server/services/multiprotocol
SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"

# Se necessário, instalar a C.4 SOMENTE na raiz do crate, nunca em src/:
# unzip -o ~/Downloads/fase8-4-5-4c4-classificacao-clientes-a-b-sem-corte-arch.zip \
#   'scripts/*' 'tests/*' 'docs/*' -d .

python3 -B tests/test_fase8_4_5_4c4_classificacao.py
python3 -B scripts/fase8_4_5_4c4_classificacao.py preflight --snapshot "$SNAPSHOT"

# Criar SOMENTE se C-v2 ainda não existe; se existe, NÃO repetir criar.
C4="$HOME/.config/rust-server/phase8-4-5-4c/classificacao-clientes-c4.json"
if test -e "$C4" || test -L "$C4"; then
  echo 'Cadastro C-v2 existente: nao sobrescrever.'
else
  python3 -B scripts/fase8_4_5_4c4_classificacao.py criar --snapshot "$SNAPSHOT" || exit 1
fi

python3 -B scripts/fase8_4_5_4c4_classificacao.py matriz --snapshot "$SNAPSHOT"
```

O `criar` nunca preenche IDs reais, não marca implantação como verdadeira, não aprova Segurança nem altera o C-v1.

### Aplicar e executar C.5

```bash
cd ~/server/services/multiprotocol
unzip -o ~/Downloads/fase8-4-5-4c5-avaliacao-operacional-a-b-sem-corte-arch.zip \
  'scripts/*' 'tests/*' 'docs/*' -d .
python3 -B tests/test_fase8_4_5_4c5_avaliacao_operacional.py

SNAPSHOT="$HOME/server_backups/fase8_4_5_2/snapshot-20261029T165042Z-1aa693fc4484"
python3 -B scripts/fase8_4_5_4c5_avaliacao_operacional.py preflight --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_4c5_avaliacao_operacional.py situacao --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_4c5_avaliacao_operacional.py plano --snapshot "$SNAPSHOT"
python3 -B scripts/fase8_4_5_4c_prontidao_corte.py avaliar --snapshot "$SNAPSHOT"
```

`avaliar` do C-v1 pode retornar **código 3** por pendências, normalmente esperado. C.5 retorna 0 para leitura válida mesmo que existam pendências, e 2 se bloquear integridade/compatibilidade.

### Evidências que devem existir antes de qualquer baixa operacional

| Identidade | No A operacional | No B laboratório | Estado inicial honesto |
|---|---|---|---|
| `bridge` | Provar serviço/processo real, configuração efetiva, reconexão e rollback do cliente | C.1 homologou fluxo da bridge isolado | ID fixo em fonte não equivale a cliente observado |
| `lab` | Identificar operadores/instâncias e obter decisão de Segurança sobre credenciais/Client IDs | CLI de IDs dinâmicos na C.2 | Conta conhecida; uso operacional não comprovado |
| `device-sensor02` | Provar dispositivo/serviço, ID efetivo, atualização e reversão | Cliente simulado na C.2 | Possibilidade de não implantação ainda não resolvida |
| `device-sensor01` | Manter revogado | Manter revogado | **Nunca reabilitar** |

Distinguir `declared-deployed` e `declared-not-deployed` de comprovação externa verificada. Uma afirmação de *não implantado* exige inventário confiável e decisão formal de exclusão do escopo; nenhuma delas baixa automaticamente o C-v1.

### Garantias e limites

1. **Somente leitura em C.5:** não escreve JSON, não lê valores de credenciais, não acessa a rede, não executa MQTT, não inicia/encerra serviços e não inicia Rust ou Mosquitto. Reutiliza a validação de branch, hash do snapshot, políticas, scripts revisados e permissões dos cadastros C.3/C.4.
2. **Cenários independentes:** nenhuma declaração do B é promovida para comprovação do A; o A continua principal.
3. **Relatório sanitizado:** mostra estados, classificação e se há referência, sem mostrar referências completas, tokens, chaves, senhas ou argumentos de processos. O relatório não é prova de operação real.
4. **Aprovação externa:** Segurança, Git/CI, janela, responsáveis, cofre, rotação, rollback do lado do cliente e snapshot FINAL antes de manutenção permanecem obrigatórios.
5. **Corte real `8883`:** sempre não autorizado. Não ligar o Mosquitto original nem repetir os ensaios isolados C.1/C.2 nesta etapa.

**Próximo marco após validar C.5:** coleta verificável das configurações e procedimentos dos clientes operacionais A, revisão de política da conta `lab` e encaminhamento separado à Segurança e ao Git/CI. **Não avançar automaticamente à 8.4.5.5.**
