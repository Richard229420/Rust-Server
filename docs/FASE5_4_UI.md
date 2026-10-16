# Fase 5.4 — Interface interativa OpenAPI 3.1.1

## Arquitetura

- Rust HTTP em `127.0.0.1:8080` continua igual, com SQLite e seus 16 workers.
- Caddy TLS em `https://localhost:8443` continua igual; **não** é necessário para a interface de laboratório.
- `python3 scripts/swagger_lab.py` inicia um servidor **somente** em `127.0.0.1:8765`.
- `http://127.0.0.1:8765/docs`: Swagger UI com arquivos JS/CSS do CDN oficial jsDelivr, versão **fixada** `swagger-ui-dist@5.33.0`; requer internet para carregar o Swagger UI.
- `http://127.0.0.1:8765/offline`: explorador básico **sem dependências externas**, usa `docs/openapi.json` e permite CRUD.
- `GET /openapi.json` entrega uma **cópia em memória** do contrato com o servidor URL `/`, para que o navegador use a mesma origem. O arquivo original `docs/openapi.json` não é alterado.
- Chamadas para `/api/v1/users...` passam por proxy Python para `127.0.0.1:8080` e usam token de sessão aleatório injetado na página. Nenhum acesso é permitido a `/metrics` pelo proxy.

## Instalação

```bash
cd ~/Downloads
unzip fase5_refinamento_5_4_interface.zip
bash fase5_ui54/instalar_fase54.sh check
bash fase5_ui54/instalar_fase54.sh apply
```

## Como iniciar

Terminal 1:

```bash
cd ~/server
cargo run --release
```

Terminal 2:

```bash
cd ~/server
python3 scripts/swagger_lab.py
```

Navegador: `http://127.0.0.1:8765/docs` ou `/offline`.

Em Swagger UI: clique no método/endpoint, **Try it out**, preencha os campos e clique **Execute**. O token é inserido automaticamente pelo script local. O POST/PUT/PATCH/DELETE altera o banco real da instância ativa — utilize **somente dados fictícios**. Reiniciar o servidor não exclui os usuários do SQLite.

A interface pode ser exibida sem o Rust, mas tentar executar uma operação retorna HTTP **502** se o backend estiver parado. Para encerrar: `Ctrl+C` em ambos os terminais.

## Segurança e restrições

- A UI usa **HTTP** apenas no loopback; não a exponha na rede/Internet, não configure port forwarding nem publique esta porta.
- A API REST **ainda não tem autenticação nem autorização**. O token do proxy limita chamadas originadas do navegador; **não é autenticação dos usuários nem substitui controles de acesso da API**.
- A UI não faz CORS. Há validação estrita de `Host`, `Origin`, `Sec-Fetch-Site`, limite de requisição e caminhos. A única conexão de saída do proxy é `127.0.0.1:8080`.
- Swagger UI usa CDN; a interface offline usa apenas recursos locais. Para instalação completamente offline, use `/offline`.
- A política CSP da UI permite jsDelivr para carregamento do Swagger UI. O pacote **não** disponibiliza Swagger UI como binário local; o fornecedor pode alterar conteúdo ou indisponibilizar recursos. A versão de CDN é fixa, mas isto não substitui integridade de supply chain.
- Evite abrir em navegadores com extensões não confiáveis ou usar dados sensíveis. O banco SQLite está fora do controle do instalador e dos testes.

## Testes

Com o Rust parado (porta 8080 livre) para o teste completo:

```bash
cd ~/server
bash scripts/test_fase54.sh
bash scripts/test_fase54.sh --full
```

Os testes da UI iniciam um **backend falso** em portas aleatórias e não modificam `data/users.sqlite3`. O teste --full reexecuta a suíte anterior com os scripts originais e seus bancos temporários.

Para verificar a integridade da instalação:

```bash
bash ~/Downloads/fase5_ui54/instalar_fase54.sh verify
```

## Remoção

Pare `swagger_lab.py` e execute:

```bash
bash ~/Downloads/fase5_ui54/instalar_fase54.sh remove
```

A remoção recusa excluir arquivos da UI que tenham sido modificados manualmente e preserva a OpenAPI 5.3 e os dados SQLite.
