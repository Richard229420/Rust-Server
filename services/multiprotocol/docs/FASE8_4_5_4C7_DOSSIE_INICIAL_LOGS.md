# Rust-Server — Dossiê inicial C.7 baseado nas evidências já apresentadas

**Classificação:** revisão preliminar, sem dados sensíveis. **Fonte:** saída de terminal `Teste fase84544c6.txt` fornecida pelo operador. **Data de consolidação:** 2026-11-04.

Este dossiê consolida o que já pode ser afirmado sem acessar o Arch Linux do usuário. **Não deve ser confundido com o registro privado que será produzido pelo coletor C.7 no host.**

## Evidências confirmadas pelos logs

| Fonte/etapa | Resultado observado | Alcance da evidência |
|---|---|---|
| Fase C.6 — teste Python | 55 testes, `OK` | Implementação de inventário e controles offline validada no Arch |
| Fase C.6 — preflight | Baseline, C-v1/C-v2, branch e fontes revisadas conferidos | Baseline para coleta passiva, não autorização de migração |
| Fase C.6 — inventário | `RUST_SERVER_MQTT_BRIDGE_PASSWORD`, `RUST_SERVER_MQTT_LAB_PASSWORD`, `RUST_SERVER_TLS_CA` declaradas | Presença de nomes de variáveis; valores e uso efetivo não verificados |
| Fase C.6 — inventário | `RUST_SERVER_MQTT_ADDR` não declarada | Apenas resultado de busca no arquivo examinado, não configuração efetiva de todos os processos |
| Fase C.6 — inventário | `multiprotocol`, `mosquitto`, `mosquitto_pub`, `mosquitto_sub`: 0 processos por nomes pesquisados | Ausência no instante e escopo da consulta; não prova ausência em outros hosts |
| Fase C.6 — índice | Criado em diretório privado; `lab`, `bridge`, `device-sensor02`: 0 referências | Nenhum documento comprobatório de A indexado até aquele momento |
| C-v1 | 21 pendências: `lab=6`, `bridge=3`, `device-sensor02=6`, `operacionais=6` | Prontidão ainda aberta; sem baixa automática |
| Segurança | `device-sensor01` continua revogado e excluído | Não reabilitar ou migrar como cliente ativo |

## Situação por cenário

**A (operacional principal):** identidade de processo/serviço efetivo `bridge`, operadores `lab` e implantação de `device-sensor02` **não comprovadas**. Não há evidência de troca real de credenciais de produção ou rollback de cada cliente real.

**B (laboratório):** ensaios C.1/C.2 foram aprovados em suas etapas anteriores, mas **não devem ser promovidos a comprovação de A**. Nenhuma credencial de laboratório deve ser usada como prova de credencial produtiva.

## Decisão de auditoria atual

**21 pendências mantidas; pronto para executar C.7 no Arch e começar revisão documental.** Este registro não substitui avaliações externas de Segurança e Git/CI, planejamento da janela, backup final sob manutenção ou autorização do corte. **Migração da porta `8883` permanece não autorizada.**
