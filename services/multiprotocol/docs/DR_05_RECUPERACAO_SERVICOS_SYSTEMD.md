# DR-05 — Recuperacao dos servicos systemd

## 1. Objetivo

Documentar a reconstrucao controlada das unidades systemd
do Rust-Server apos perda do sistema operacional ou SSD.

Este procedimento nao autoriza ativacao operacional,
migracao MQTT, alteracao de certificados ou mudancas
nas unidades atualmente instaladas.

## 2. Baseline de referencia

Repositorio: Richard229420/Rust-Server
Branch: feature/fase8-4-inventory-dynsec

Commit de referencia:
ce49a0494c937775db8b2ba78c9f567100a5825a

Ambiente validado:
- Arch Linux
- Rust e Cargo 1.99.0
- Servidor HTTP 0.1.0
- Multiprotocolo 0.2.2

## 3. Unidades identificadas

Unidades de usuario:

1. rust-server-mqtt-lab-8884.service
2. rust-server-mqtt-tls-monitor.service
3. rust-server-mqtt-tls-monitor.timer

Origem das unidades operacionais:

~/.config/systemd/user/

Permissoes observadas:
- Proprietario: arch:arch
- Arquivos: 0600

O laboratorio MQTT 8884 foi observado ativo.
O monitor TLS utiliza Type=oneshot.
O timer estava ativo, habilitado e aguardando execucao.

## 4. Parametros preservados nos modelos

Laboratorio MQTT:
- Type=simple
- StartLimitIntervalSec=60
- StartLimitBurst=3
- Restart=on-failure
- RestartSec=5
- UMask=0077
- NoNewPrivileges=true
- WantedBy=default.target

Monitor TLS:
- Type=oneshot

Timer:
- OnCalendar=*-*-* 09:00:00
- Persistent=true
- AccuracySec=5min
- Unit=rust-server-mqtt-tls-monitor.service
- WantedBy=timers.target

## 5. Modelos versionaveis

Diretorio:

services/multiprotocol/deploy/systemd/

Arquivos:

- rust-server-mqtt-lab-8884.service.example
- rust-server-mqtt-tls-monitor.service.example
- rust-server-mqtt-tls-monitor.timer.example

Os modelos sao nao operacionais.

Os comandos ExecStart foram substituidos por:

ExecStart=/usr/bin/false

Nao instalar, iniciar ou habilitar esses modelos diretamente.

A unidade MQTT usa Restart=on-failure e podera tentar
reiniciar repetidamente caso seja instalada sem adaptacao.

## 6. Dependencias nao recuperadas pelo Git

A recuperacao completa exige verificacao separada de:

- Credenciais e configuracoes privadas
- Certificados e chaves da PKI v2
- Bancos SQLite e backups consistentes
- Pacotes e bibliotecas do sistema
- Caminhos e binarios utilizados pelos servicos
- Configuracoes locais dos brokers
- Politicas de autorizacao e seguranca

Nenhuma chave privada, senha ou banco operacional
devera ser incorporado ao repositorio Git.

## 7. Procedimento de recuperacao controlada

1. Recuperar o codigo do GitHub.
2. Confirmar a branch e o commit de referencia.
3. Recompilar os projetos Rust em ambiente isolado.
4. Conferir os modelos systemd versionados.
5. Identificar dependencias ausentes.
6. Recuperar dados e credenciais somente pelos
   respectivos procedimentos homologados.
7. Reconstruir ExecStart apos revisao de seguranca.
8. Validar as unidades em diretorio temporario.
9. Verificar permissoes e dependencias.
10. Solicitar autorizacao antes de qualquer ativacao.

Nao executar automaticamente:
- systemctl enable
- systemctl start
- systemctl restart
- systemctl daemon-reload

A ativacao devera ser objeto de procedimento separado
e de aprovacao operacional.

Atencao: Persistent=true pode ocasionar execucao
de compensacao apos habilitacao do timer.

## 8. Evidencias obtidas

DR-01: baseline Git e Rust registrado.
DR-02: clonagem isolada do GitHub aprovada.
DR-03: cargo check e cargo test --no-run aprovados
       para HTTP e multiprotocolo.
DR-04: quatro bancos SQLite com integrity_check OK.
       Restauracao e backup externo pendentes.
DR-05: tres modelos systemd criados.
       systemd-analyze verify aprovado.

A validacao systemd ocorreu em diretorio temporario,
sem instalar ou iniciar unidades.

## 9. Restricoes e pendencias

- PR #2 sem autorizacao de merge.
- MQTT 8883 permanece em NO-GO.
- Custodia PKI v2 parcialmente homologada.
- Pendencias C-V1 permanecem abertas.
- Recuperacao SQLite ainda nao homologada.
- Recuperacao dos servicos em instalacao limpa pendente.
- Dependencias e comandos operacionais nao restaurados.

## 10. Criterios de conclusao da DR-05

- Modelos revisados e sanitizados.
- Sintaxe systemd aprovada.
- Documentacao revisada.
- Verificacoes de seguranca aprovadas.
- Commit e CI concluidos.
- Nenhuma alteracao operacional realizada.

O encerramento da DR-05 nao implica aprovacao
de recuperacao operacional integral.
