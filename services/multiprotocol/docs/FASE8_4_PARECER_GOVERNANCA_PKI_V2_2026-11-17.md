# Rust-Server — Parecer técnico de governança e segurança da PKI v2

**Data de referência:** 17/11/2026  
**Projeto:** Rust-Server — Fase 8.4  
**Branch de referência:** `feature/fase8-4-inventory-dynsec`  
**Origem do encaminhamento:** conversa *Rust-Server — Chaves e Segurança*  
**Natureza:** parecer de governança para registro em dossiê; não constitui autorização operacional  
**Classificação do parecer:** **FAVORÁVEL COM RESSALVAS AOS CONTROLES LOCAIS — CUSTÓDIA PARCIALMENTE HOMOLOGADA — NO-GO OPERACIONAL**

## 1. Objetivo e alcance

Consolidar o encaminhamento de Segurança recebido em 17/11/2026 e relacioná-lo às evidências de versionamento e CI/CD previamente verificadas no âmbito do Rust-Server. Distinguir controles técnicos demonstrados, lacunas de custódia e decisões expressamente **não concedidas**.

**Limitação de evidência:** este documento se baseia no resumo formal encaminhado pela conversa de Chaves e Segurança e nos resultados de Git/CI anteriormente apresentados. Não representa uma nova inspeção independente das chaves, certificados, backups ou dispositivos de custódia. Nenhuma chave privada, credencial, conteúdo de backup ou material de assinatura deve ser incorporado ao dossiê versionado.

## 2. Controles locais de Segurança com avaliação favorável

Segundo o encaminhamento de Segurança de 17/11/2026, foram confirmados:

| Controle | Resultado reportado | Observação de alcance |
| --- | --- | --- |
| Chaves privadas `ca.key` e `server.key` | Permissões `0600`, proprietário `arch`, contagem de links igual a 1 por arquivo | Custódia local; não comprova cópia externa nem recuperação |
| Diretórios de custódia | Permissões `0700` | Proteção local de acesso |
| Certificados CA v2 e servidor v2 | Extensões X.509 adequadas | Validação técnica dos certificados |
| Validade da CA v2 | Até **07/11/2028** | Exige acompanhamento de validade e rotação |
| Validade do certificado de servidor | Até **07/05/2027** | Exige acompanhamento de validade e rotação |
| Validação TLS | Validação X.509 estrita aprovada para `localhost` e `127.0.0.1` | Alcance informado: laboratório |
| Monitoramento TLS | Habilitado; execução bem-sucedida em **16/11/2026** | Evidência pontual informada; continuidade requer monitoramento |
| Backups GPG | Cópias locais pré e pós-renovação presentes, permissões `0600` | Mesmo NVMe do Arch Linux |
| Integridade do backup pós-renovação | SHA-256 comprovado | Não equivale a restauração comprovada |
| Compatibilidade MQTT | PKI v2 compatível criptograficamente com o laboratório **8884** | Não autoriza migração para **8883** |

**Conclusão deste bloco:** os controles técnicos locais da PKI v2 receberam avaliação favorável no escopo declarado. Não há base para estender essa conclusão à custódia integral ou à operação de produção.

## 3. Pendências impeditivas da homologação integral de custódia

O encaminhamento informa que os backups estão armazenados no **mesmo NVMe** do sistema Arch Linux. A concentração de originais e cópias no mesmo meio físico mantém uma dependência comum diante de falha, perda ou indisponibilidade desse armazenamento.

A homologação integral exige evidências verificáveis dos seguintes itens:

1. **Cópia criptografada independente:** comprovação de backup em dispositivo físico ou armazenamento independente, com localização e inventário registrados sem exposição de segredos.
2. **Recuperação isolada da CA v2:** ensaio documentado de restauração da chave privada da CA v2 em ambiente segregado, com conferência de integridade e resultado, sem publicar a chave ou sua senha.
3. **Inventário das cópias antigas:** identificação, classificação, finalidade, condição de proteção e destinação das cópias anteriores.
4. **Retenção, descarte e acesso:** política documentada para retenção, descarte seguro, responsáveis e controle de acesso à chave de assinatura e aos backups.

Até que essas quatro frentes sejam comprovadas e avaliadas pela instância de Segurança, o estado permanece **HOMOLOGAÇÃO PARCIAL**. A mera existência de uma cópia criptografada externa não é suficiente para declarar recuperação testada ou custódia integral homologada.

## 4. Evidências correlatas de Git e CI/CD

A trilha de versionamento e integração contínua foi concluída em escopo próprio, independente da homologação de custódia:

| Referência | Situação documentada |
| --- | --- |
| Branch | `feature/fase8-4-inventory-dynsec` |
| Commit de correção de CI | `82a2870ab095905ef36e5d1cceffa5e97ad66aa1` |
| Pull Request | [PR #2](https://github.com/Richard229420/Rust-Server/pull/2), com destino `main`; **OPEN** na última consulta apresentada |
| CI do push | [Run 43295358456](https://github.com/Richard229420/Rust-Server/actions/runs/43295358456) — `success` |
| CI do pull request | [Run 43295369745](https://github.com/Richard229420/Rust-Server/actions/runs/43295369745) — verificações aprovadas na consulta apresentada |
| Cobertura de checks apresentada | 6/6 checks aprovados: Segurança/offline, Rust servidor HTTP e Rust multiprotocolo nos eventos `push` e `pull_request` |
| Arquivos novos previamente registrados | 70 arquivos, organizados em preparação/paridade, controles C.1–C.10 e laboratório BRI 8901; workflow de CI versionado separadamente |

A execução padrão do CI valida os testes configurados, a compilação e o Clippy estrito. **Não comprova, por si só, ensaios operacionais reais nem a execução dos testes BRI 8901 marcados `#[ignore]`.** O estado do PR e os checks devem ser reconfirmados se o commit ou as regras de proteção da branch forem alterados.

## 5. Limites e decisões não concedidas

Permanecem expressamente **não autorizados** por este parecer:

- Merge do PR #2 na branch `main`.
- Novo `push` ou alteração de versão como consequência automática da homologação parcial; alterações futuras exigem fluxo próprio de revisão.
- Deploy, promoção para produção ou corte/migração MQTT para a porta **8883** (**NO-GO**).
- Alteração de certificados, chaves, credenciais, ACLs, identidades de dispositivos ou bancos operacionais.
- Encerramento das **21 pendências C-V1**.
- Tratamento de C.9/C.10, dos backups GPG, dos resultados do CI ou da compatibilidade no laboratório 8884 como autorização de operação.

**Regra de segregação:** o dossiê Git deve conter apenas referências, inventários não sensíveis, metadados, hashes e decisões devidamente revisados. Chaves privadas, segredos, arquivos de credenciais, backups e material que permita sua recuperação permanecem fora do repositório e de artefatos/logs do CI.

## 6. Parecer conclusivo

**Parecer técnico:** **favorável com ressalvas aos controles locais da PKI v2**, conforme as evidências relatadas pela conversa de Segurança. **Não favorável à homologação integral da custódia neste momento**, por ausência de comprovação de cópia independente, recuperação isolada da CA v2, inventário/classificação de cópias antigas e política de retenção/descarte/acesso.

**Decisão de governança:** **APROVAÇÃO PARCIAL — NO-GO OPERACIONAL**. A aprovação de Git/CI/CD é válida somente para seu escopo técnico e não altera a decisão de Segurança. O PR #2 deve permanecer sem merge até a existência de autorizações específicas; a migração MQTT 8883 continua bloqueada.

## 7. Condições para emissão do parecer definitivo de custódia

Após a apresentação das evidências independentes e do teste de recuperação isolada, a conversa *Chaves e Segurança* deverá reavaliar formalmente os quatro itens da seção 3 e consignar, com data e identificação da evidência, a decisão de homologação integral, parcial ou reprovação. O parecer deverá ser atualizado sem reclassificar retroativamente como executados testes ou controles que ainda não ocorreram.

A eventual homologação integral de custódia **não concederá automaticamente** autorização para merge, deploy, mudança de ACL, rotação operacional ou corte 8883: essas decisões continuam sujeitas a avaliação e aprovação próprias.

---

**Registro elaborado para inclusão controlada no dossiê da Fase 8.4.** Nenhuma alteração foi realizada automaticamente no repositório Rust-Server, nos sistemas de custódia ou no GitHub.
