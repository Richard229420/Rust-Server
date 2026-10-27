## Resumo da alteracao
Descreva o objetivo e as alteracoes implementadas.

## Impactos
- [ ] Alteracoes Rust revisadas
- [ ] Configuracoes de MQTT / HTTPS / TCP-TLS revisadas quando aplicavel
- [ ] Migrations e persistencia revisadas quando aplicavel
- [ ] Nenhum segredo, chave privada, token de dispositivo ou banco de producao incluido

## Validacao automatica (GitHub Actions)
- [ ] Seguranca - arquivos e testes offline
- [ ] Rust - servidor-http
- [ ] Rust - multiprotocolo

## Validacao no laboratorio (quando afeta seguranca de dispositivos)
- [ ] Broker parado durante alteracoes de contas e ACLs
- [ ] `sensor02` autenticou com a credencial rotacionada
- [ ] Isolamento MQTT de dispositivos passou (7/7)
- [ ] `sensor01` consta como `revoked` no inventario REAL
- [ ] Teste `test_phase8_3_devices.sh --revoked sensor01 sensor02` passou apos reiniciar o broker
- [ ] Evidencias revisadas sem publicar senhas, tokens, chaves privadas nem logs sensiveis

## Checklist de merge
- [ ] CI aprovado
- [ ] Revisao por outra pessoa, quando disponivel
- [ ] Testes locais obrigatorios aprovados (nao substituidos pelo CI offline)
- [ ] Versao e changelog avaliados, se for lancamento

**Importante:** marcar esta lista nao substitui a execucao nem a revisao dos testes. Na Fase 8.3, nao fazer merge na `main` sem revogacao real comprovada.
