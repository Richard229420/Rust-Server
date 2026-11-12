# Rust-Server Fase 8.4 — Testes negativos BRI em 8901 (v2)

## Motivo da revisao

O v1 exigia que uma assinatura nao permitida recebesse SUBACK 0x80 no Mosquitto com `acl_file` classico. Nesse mecanismo, o broker pode confirmar SUBSCRIBE, mas aplicar a ACL durante a entrega. Por isso, o teste v1 pode falhar mesmo com acesso bloqueado. O v2 nao relaxa o controle: demonstra **entrega ao leitor autorizado** e **nao entrega ao leitor sem READ** do MESMO topico/mensagem.

## Isolamento e escopo

- Usa `127.0.0.1:8901`, certificados de um dia e credenciais aleatorias descartaveis, distintos do MQTT 8883/8884.
- Reutiliza `scripts/testar_bridge_bri_8901.py` para preparar o broker efemero. Acrescenta usuario `auditor` apenas ao arquivo de senhas/ACL temporario: READ `bus/alerts`.
- `bridge`: WRITE `bus/alerts`; `injector`: WRITE `lab/alerts`, sem READ `bus/#`; `auditor`: READ `bus/alerts`.
- Autenticacao incorreta e CA nao confiavel devem ser rejeitadas.
- ACL: `injector` assina `bus/#`; `bridge` publica `bus/alerts` (QoS1, marcador aleatorio, nao retido); `auditor` DEVE receber a mensagem exata; `injector` NAO DEVE recebe-la. Se o event loop cair, bloqueia o resultado.
- Somente broker do cenario B; nao implementa rotacao, rollback ou prova de runtime do cenario A. Nao registra C.10 nem encerra nenhuma das 21 pendencias.

## Instalacao

Pacote pode ser extraido com `unzip -n` dentro de `~/server`, pois usa nomes v2 e nao altera o arquivo v1.

```bash
cd ~/server/services/multiprotocol
python3 -B tests/test_bri_negativos_v2_controlador.py
cargo test --offline --locked --test bridge_fase8_4_bri_negativos_v2 --no-run
python3 -B scripts/testar_bridge_bri_negativos_v2_8901.py
```

Os testes Rust sao `#[ignore]`, portanto `cargo test` comum nao conecta ao broker. O comando Python cria e encerra o Mosquitto com TLS e limpa arquivos descartaveis em erros tratados. O controlador omite a saida bruta Rust do terminal para evitar vazamentos de dados de laboratorio.

### O que o teste nao prova

- Que o codigo `bridge::start()` utiliza as mesmas identidades em operacao (essa prova requer teste isolado dedicado e, mais tarde, evidencias do cenario A).
- Que `SubAck` de sucesso significa acesso de leitura. O v2 explicitamente nao assume isso.
- Que rotacao e rollback de credenciais funcionam.
- Que nenhuma entrega poderia ocorrer depois da janela de observacao; a prova e limitada ao teste reproduzivel, ao mesmo topico e ao mesmo marcador, com conexoes ativas e auditor autorizado.
- Que a C-V1 pode ser encerrada: todas as 21 pendencias permanecem abertas e o corte 8883 nao esta autorizado.

### Se falhar

O controlador mostra qual teste falhou (`auth_rejeitada`, `ca_nao_confiavel` ou `acl_entrega_negada`), sem mostrar senhas. Nao remova as assercoes; revise as saidas localmente antes de enviar qualquer trecho. Arquivos historicos e estado C.9/C.10 sao preservados.
