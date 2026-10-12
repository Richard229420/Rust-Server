# Expansões planejadas: HTTPS, mensagens e protocolos

## Prioridade alta: HTTPS

**Primeira opção para laboratório/implantação controlada:** Caddy como reverse proxy com TLS, mantendo este servidor Rust em `127.0.0.1:8080` (exemplo em `observability/Caddyfile.example`). O proxy administra certificados e cifra a comunicação do cliente ao proxy. Isso **não conserta** eventuais falhas do parser HTTP Rust. Não exponha o backend diretamente.

**Alternativa didática futura:** usar `rustls` diretamente no servidor, estudando TLS 1.3, certificados, SNI e expiração/renovação. Exige testes de TLS e revisão de segurança.

## Mensageria (componentes ou serviços separados)

- **AMQP / RabbitMQ:** tarefas assíncronas e filas duráveis, consumidor e produtor, confirmações, retry e dead-letter; integração ao servidor HTTP por cliente de broker, não como um segundo parser no `server.rs`.
- **NATS:** mensagens pub/sub, request/reply e, quando necessário, persistência via JetStream.
- **Apache Kafka / Redpanda:** eventos e logs de alto volume; seria uma fase mais complexa.
- **Redis Streams:** filas e grupos de consumidores com Redis.
- **WebSocket:** canal bidirecional cliente/servidor que começa com handshake HTTP; não substitui broker de mensagens e envolve framing e conexões persistentes.
- **SSE:** eventos enviados pelo servidor a navegadores por HTTP; simples para atualizações unidirecionais, mas exigiria suporte a streaming na aplicação.

MQTT também poderia ser integrado como cliente de broker para IoT, mas não é preciso hospedar um broker dentro do servidor HTTP.

## Outros protocolos e camadas TCP/IP

- **TCP e UDP** são protocolos de transporte; o projeto já utiliza TCP por meio da biblioteca padrão Rust. Para aprender UDP, crie um módulo ou programa de laboratório separado.
- **DNS** resolve nomes para endereços, normalmente usando UDP/TCP. É melhor criar um cliente DNS de diagnóstico separado, não embutir um resolvedor completo neste servidor.
- **HTTP/2 e gRPC** são evoluções distintas, com multiplexação/framing diferentes. HTTP/3 é baseado em QUIC sobre UDP.
- **SMTP** é útil para notificações, mas deve ser integrado por biblioteca/serviço de e-mail em vez de reinventar o servidor SMTP.
- **SSH e SFTP** são protocolos de acesso/transferência e não precisam coexistir na mesma porta/processo HTTP.

## Sequência sugerida

1. Concluir e validar a Fase 3 (testes, métricas, limites).
2. Adicionar HTTPS via proxy reverso e testar certificados.
3. Criar API REST de laboratório com validação e testes de autenticação/autorização.
4. Integrar a API a um broker (RabbitMQ AMQP ou NATS) para processar tarefas assíncronas.
5. Considerar WebSocket/SSE e, separadamente, gRPC/HTTP2 e laboratórios TCP/UDP/DNS.
