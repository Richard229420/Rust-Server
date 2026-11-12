#!/usr/bin/env python3
"""8.4.5.4-C.5: avaliacao passiva da prontidao MQTT nos cenarios A/B.

Somente leitura. Depende de C-v1 (C.3) e do cadastro C-v2 (C.4).
A declaracao de implantacao nao comprova cliente operacional; B nunca aprova A.
Nao altera broker, credenciais, cadastros, certificados, Git ou snapshot.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
import sys

import fase8_4_5_2_preparar as p2
import fase8_4_5_4c_prontidao_corte as c
import fase8_4_5_4c3_evidencias as c3
import fase8_4_5_4c4_classificacao as c4

PHASE = '8.4.5.4-C.5'
READ_ONLY_ACTIONS = ('preflight', 'situacao', 'plano')
ACTIONS = READ_ONLY_ACTIONS


class Block(Exception):
    """Negativa que nao imprime dados particulares."""


@dataclass(frozen=True)
class Context:
    fingerprint: str
    pending: tuple[str, ...]
    legacy: dict
    classification: dict


def verified_context(project: Path, snapshot: Path, private: Path,
                     backups: Path, plugin: Path) -> Context:
    """Valida em leitura os mesmos marcos de C.4, exigindo cadastro C-v2 valido."""
    c.verify_branch(project)
    fingerprint, _ = c.baseline(snapshot, backups, project, private, plugin)
    c3.verify_bridge_source(project)
    legacy = c.load_model(private)
    pending = c4.reviewed_legacy(legacy, fingerprint)
    classification = c4.read_registry(private, fingerprint)
    c4.validate(classification, fingerprint)
    if (legacy.get('cutover_authorized') is not False or
            classification.get('cutover_authorized') is not False or
            any(classification['gates'].values())):
        raise Block('autorizacao de corte ou gate inesperado')
    return Context(fingerprint, tuple(pending), legacy, classification)


def counts(pending: tuple[str, ...]) -> dict[str, int]:
    """Conta pendencias C-v1 por identidade, sem supor que a fase esteja vazia."""
    output = {name: 0 for name in c.ACCOUNTS}
    output['operacionais'] = 0
    for item in pending:
        owner = None
        for name in c.ACCOUNTS:
            if (item.endswith(': ' + name) or
                    item.startswith('confirmacao pendente (' + name + '):')):
                owner = name
                break
        if item.startswith('criterio operacional pendente:'):
            owner = 'operacionais'
        if owner is None:
            raise Block('formato de pendencia desconhecido: nao inferir aprovacoes')
        output[owner] += 1
    return output


def row_summary(record: dict) -> str:
    """Nao expoe referencia fornecida pelo operador nem supostos IDs de producao."""
    return (record['client_class'] + '; politica=' + record['client_id_policy'] +
            '; implantacao=' + record['deployment'] +
            '; evidencia=' + ('referenciada' if record['evidence_ref'] else 'nao-registrada'))


def safe_report(context: Context) -> str:
    """Resultado de prontidao; nunca muda C-v1/C-v2 nem autoriza corte."""
    c4.validate(context.classification, context.fingerprint)
    remaining, _ = c.validate_model(context.legacy, context.fingerprint)
    if tuple(remaining) != context.pending:
        raise Block('cadastro C-v1 alterado durante avaliacao')
    group = counts(context.pending)
    output = [
        '=== 8.4.5.4-C.5 — AVALIACAO OPERACIONAL A/B (SOMENTE LEITURA) ===',
        'CENARIO A: OPERACIONAL PRINCIPAL; cliente real NAO comprovado por classificacao.',
        'CENARIO B: LABORATORIO; evidencias C.1/C.2 NAO substituem comprovacao em A.',
    ]
    for scenario in c4.SCENARIOS:
        output.append('MATRIZ ' + scenario + ':')
        for name in c.ACCOUNTS:
            record = context.classification['scenarios'][scenario]['identities'][name]
            output.append('  ' + name + ': ' + row_summary(record))
    output.extend([
        'C-V1: ' + str(len(context.pending)) + ' pendencias (' +
        ', '.join(name + '=' + str(group[name]) for name in (*c.ACCOUNTS, 'operacionais')) + ').',
        'LAB EM A: politica CLI pendente de aprovacao de Seguranca, mesmo se proposta na C.4.',
        'BRIDGE: Client ID da fonte Rust nao comprova execucao operacional.',
        'SENSOR02: declaracao C-v2 nao comprova dispositivo fisico, firmware ou reconexao.',
        'REVOGADO: device-sensor01 nao pode ser reabilitado.',
        'GATES: Seguranca, Git/CI e prontidao operacional NAO aprovados por este programa.',
        'BACKUP: snapshot 8.4.5.2 nao substitui captura final em janela autorizada.',
        'RESULTADO: NAO HABILITADO PARA CORTE; 8883 NAO AUTORIZADO.',
    ])
    return '\n'.join(output)


def plan(context: Context) -> str:
    c4.validate(context.classification, context.fingerprint)
    c.validate_model(context.legacy, context.fingerprint)
    output = [
        '=== 8.4.5.4-C.5 — COLETA DE EVIDENCIAS PARA A (SEM EXECUTAR CLIENTES) ===',
        '1 BRIDGE A: documentar host e forma de inicializacao REAL (servico ou comando),',
        '  binario/versao, endereco TLS efetivo e Client ID. Nao revelar senha ou ambiente.',
        '  Em homologacao, testar troca e retorno de credenciais do cliente efetivo.',
        '2 LAB A: confirmar se conta CLI serve a operadores reais; inventariar instancias',
        '  e obter aprovacao de Seguranca para IDs/contas dedicadas e ACL minima.',
        '  IDs dinamicos de B nao comprovam cliente operacional A.',
        '3 SENSOR02 A: identificar host ou dispositivo, firmware/servico, configuracao do',
        '  Client ID efetivo e mecanismo de update/retorno; se nao implantado, comprovar',
        '  a nao implantacao e decidir formalmente exclusao do escopo do corte.',
        '4 SEGREDOS: custodiante, cofre, canal autenticado, procedimento de rotacao',
        '  e retencao curta e controlada da credencial legada durante rollback.',
        '5 ROLLBACK POR CLIENTE: comprovar reconexao antiga em homologacao para bridge,',
        '  lab e sensor02, conforme os clientes realmente incluidos no escopo.',
        '6 OPERACAO: responsaveis, janela, monitoramento, gatilhos de abortar,',
        '  snapshot FINAL de manutencao e teste de recuperacao planejado.',
        '7 GATES: revisao independente de Seguranca e Git/CI; registrar decisoes',
        '  fora deste script. O script NAO confirma nenhuma etapa automaticamente.',
        'B: manter C.1/C.2 e isolamento do laboratorio como ensaios de homologacao.',
        'NAO EXECUTAR: mosquitto, credenciais produtivas, mudanca de ACL, git push,',
        '  rollback real ou migracao para 8883.',
        'RESULTADO: plano de coleta; CORTE 8883 NAO AUTORIZADO.',
    ]
    return '\n'.join(output)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--backups-root', type=Path,
                        default=Path.home() / 'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    args = parser.parse_args(argv)
    try:
        project, snapshot, private, backups, plugin = (
            value.absolute() for value in (
                args.project_root, args.snapshot, args.private_root,
                args.backups_root, args.plugin_path))
        ctx = verified_context(project, snapshot, private, backups, plugin)
        if args.action == 'preflight':
            print('APROVADO: baseline, cadastro C-v1/C.3 e matriz C-v2/C.4 conferidos.')
            print('PENDENCIAS C-V1: ' + str(len(ctx.pending)) + '; CORTE 8883 NAO AUTORIZADO.')
        elif args.action == 'situacao':
            print(safe_report(ctx))
        else:
            print(plan(ctx))
        return 0
    except (Block, c.Block, c3.Block, c4.Block, p2.Block,
            ValueError, TypeError, OSError):
        print('BLOQUEIO: C-v1/C-v2, snapshot, branch ou fontes nao conferem; '
              'nenhum broker alterado. CORTE 8883 NAO AUTORIZADO.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
