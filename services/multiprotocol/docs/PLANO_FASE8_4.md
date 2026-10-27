# Fase 8.4 — Seguranca dinamica e operacao auditavel (proposta)

## Premissas

- Execucao e fonte de verdade: **Arch Linux**, em `~/server`.
- Sem migracao de banco de dados, configuracoes ou servicos do Debian.
- Preservar HTTP 8080, HTTPS 8443, MQTT TLS 8883, TCP/TLS 7001 e bridge.
- Validacao da 8.3: `sensor01` revogado, `sensor02` ativo. Nao reutilizar IDs revogados.
- Sem exposicao a LAN/Internet durante a fase.

## Objetivo

Migrar gradualmente o gerenciamento das identidades MQTT para a API de seguranca dinamica do Mosquitto, com revogacao de clientes conectados, sem reiniciar todo o broker, mantendo ACLs individualizadas, rollback verificado e auditoria. Avaliar se o plugin `dynamic-security` da versao instalada atende ao contrato antes de converter estados.

## Etapas propostas

1. **8.4.1 — Inventario e backup:** auditar versao e caminho do plugin `dynamic-security`, salvar snapshot privado do estado atual e documentar rollback. Nao inserir segredos no Git.
2. **8.4.2 — Experimento isolado:** subir um broker de teste somente em loopback, com porta separada e certificados de teste; configurar administrador, cliente sensor e papeis minimos. Nao alterar o broker 8883 existente.
3. **8.4.3 — Controle por identidade:** vincular usuario a `client ID` se suportado; ACL escrita `lab/sensors/<ID>/#`, leitura `bus/sensors/<ID>/#`; nenhuma leitura cruzada ou wildcard indevido.
4. **8.4.4 — Rotacao/revogacao online:** experimentar `mosquitto_ctrl dynsec setClientPassword`, `disableClient`, `deleteClient`; provar desconexao de cliente ativo, negacao de reconexao e permanencia do outro dispositivo.
5. **8.4.5 — Migração segura:** reconciliar inventario local e estado do plugin, preparar roteiro reversivel e migrar o broker real somente depois de testes de regressao, sem mesclar regras antigas e novas inadvertidamente.
6. **8.4.6 — Operacionalizacao:** logs de auditoria sem segredos, cotas por classe de cliente, recuperacao, reinicio e medicao de indisponibilidade, documentar proxima integracao com systemd.

## Testes de aceite

- Revogacao de dispositivo **conectado** encerra sessao e impede novo login sem reiniciar o broker.
- Atualizacao de senha invalida segredo anterior e preserva conta atual.
- Outro sensor permanece funcional durante revogacao/rotacao.
- Sensor A nao le nem publica topicos do sensor B; `lab` segue sem direitos de sensores.
- Cliente nao assume identidade alheia por `client ID`, quando o plugin suporta associacao.
- Falha de migracao restaura estado antigo sem ampliar privilegios.
- Sem tokens, certificados privados, snapshots ou SQLite no Git.
- HTTP/HTTPS/MQTT/TCP continuam passando nos testes de regressao.

## Fora do escopo imediato

- mTLS por dispositivo (avaliar em Fase 8.5).
- PostgreSQL ou alteracoes no esquema de dados do HTTP.
- Exposicao publica do listener MQTT.

## Referencias tecnicas

- https://mosquitto.org/documentation/dynamic-security/
- https://mosquitto.org/man/mosquitto_ctrl-1.html
- https://mosquitto.org/man/mosquitto-conf-5.html
