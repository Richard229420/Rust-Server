# Fase 8.4.3 — Rastreabilidade do vínculo de identidade MQTT e Client ID

**Projeto:** Rust-Server / `services/multiprotocol`
**Branch:** `feature/fase8-4-inventory-dynsec`
**Natureza:** documentação de rastreabilidade, sem nova implementação e sem decisão geral de segurança.

## Escopo identificado

A Fase 8.4.3 trata da associação entre a identidade MQTT autenticada (`username`) e o `Client ID`, no laboratório Dynamic Security isolado, de modo a reduzir a possibilidade de um cliente utilizar a identidade atribuída a outro dispositivo. Os controles por tópico e a segregação entre dispositivos foram estabelecidos nas etapas anteriores e continuam como requisitos complementares.

Não existe, no material auditado, um script independente nomeado `fase8_4_3`. Essa identificação de fase corresponde a um controle **integrado aos scripts e testes adjacentes**, e não a uma funcionalidade adicional inventada por esta documentação.

## Arquivos que fornecem rastreabilidade

- `../scripts/fase8_4_2_lab.py`: preparação do laboratório Mosquitto Dynamic Security e das identidades isoladas.
- `../scripts/test_fase8_4_2_isolamento.py`: testes de isolamento MQTT com TLS e entrega efetiva no laboratório.
- `../scripts/fase8_4_4_online.py`: operação online que verifica a vinculação antes da rotação/revogação.
- `../tests/test_fase8_4_4_online.py`: testes offline de restrições de identidade, inclusive rejeição de `username` alheio.
- `FASE8_4_2_LAB_DYNSEC.md` e `FASE8_4_4_ROTACAO_REVOGACAO_ONLINE.md`: contexto e instruções das fases adjacentes.

## Evidências observadas no laboratório

- O teste online da Fase 8.4.4 registrou: `APROVADO: vinculo username/Client ID e sensor02 operacional`.
- Os testes offline da Fase 8.4.4 incluem a rejeição de `username` alheio.
- O conjunto de testes MQTT do laboratório registrou isolamento entre `sensor01` e `sensor02` com entrega real.
- A operação posterior de revogação deixou `sensor01` desabilitado **somente no broker 8884**, preservando o broker 8883 e a operação de `sensor02`.

Estas são evidências específicas registradas nos testes. Elas **não** constituem aprovação geral da segurança, e a documentação não afirma a existência de uma suíte autônoma da Fase 8.4.3.

## Limites e prevenção de regressões

O CI deve executar apenas os testes **offline** desta etapa e das fases adjacentes. Não executar `apply`, alterações de conta ou ações contra o broker 8884 no GitHub Actions. Não reexecutar testes que exijam `sensor01` ativo sem restaurar deliberadamente um ambiente de teste separado. Senhas, tokens, opções `.opts`, backups e material de CA privada permanecem fora do Git.

A decisão de segurança geral permanece registrada neste chat, sem ser antecipada por um commit, Pull Request ou merge.
