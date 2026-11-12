#!/usr/bin/env python3
"""Fase 8.4.5.4-C: consolidacao auditavel SEM CORTE, somente leitura.

Confere evidencias ESTATICAS, a integridade do snapshot e a estrutura de prontidao
privada. Aprovacoes de seguranca/Git/CI e identificadores operacionais reais
NUNCA sao inferidos a partir dos ensaios de laboratorio ou deste script.

Nao inicia Mosquitto, nao chama comandos MQTT e nao escreve em nenhum arquivo.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys

import fase8_4_5_4c_prontidao_corte as c
import fase8_4_5_2_preparar as p2
import fase8_4_5_3_ensaio as p3
import fase8_4_5_4b_paridade_producao as p4b

BRANCH = 'feature/fase8-4-inventory-dynsec'
# SHA256 dos arquivos efetivamente distribuidos nas versoes C, C.1 corrigida e C.2
# que foram submetidas aos ensaios registrados pelo usuario em 03/11/2026.
# Se alguem alterar as fontes, exige nova revisao em vez de atribuir a elas a prova antiga.
REVIEWED_SCRIPTS = {
    'scripts/fase8_4_5_4c_prontidao_corte.py':
        '8f264acd0ab3eb0619e61b88d95e301e51a12a940586dfa9d41c7015ec4877b9',
    'scripts/fase8_4_5_4c1_bridge_rust.py':
        '644ca1a589d61d67d07360f204439c954f2bef37e396eae1c386a5eb14c1b172',
    'scripts/fase8_4_5_4c2_clientes_mqtt.py':
        'd2a2edf7cd7246355bad7136981634f8053f2d70de6e02f7ac82533f5149f233',
}
# Conforme saídas enviadas pelo usuário. Não se confundem com testes reexecutados agora.
LOGGED_EVIDENCE = {
    'C1_TESTS': '47/47 testes Python — log fornecido',
    'C1_LIVE': 'Bridge Rust + TLS/CONNACK, MQTT<->Bus, reconexao, rotacao e retorno — log fornecido',
    'C2_TESTS': '55/55 testes Python — log fornecido',
    'C2_LIVE': 'lab CLI e sensor02, ACL/DEFAULT DENY, desabilitacao, reconexao, rotacao e retorno — log fornecido',
    'SNAPSHOT': '20 arquivos, SHA-256 e manifesto aprovados apos ensaio — log fornecido',
    'PORTS': 'sem listeners em 8883/8884/8895/8896 ao final do ensaio — log fornecido',
}

class Block(Exception):
    """Erro estatico; nunca apresenta material dos arquivos privados."""


def need(condition: bool, message: str) -> None:
    if not condition:
        raise Block(message)


def checked_source(path: Path, limit: int = 128 * 1024) -> bytes:
    """Ler arquivo de código com limites, checar dono e rejeitar symlink/hardlink."""
    try:
        s = path.lstat()
        need(stat.S_ISREG(s.st_mode) and not path.is_symlink() and
             s.st_nlink == 1 and s.st_uid == os.geteuid() and 0 < s.st_size <= limit,
             'arquivo de fonte alterado, ausente ou inseguro')
        return p2.check_regular(path, private=False, limit=limit)
    except (OSError, p2.Block):
        raise Block('arquivo de fonte ausente ou inseguro') from None


def verified_sources(project: Path) -> None:
    for relative, sha in REVIEWED_SCRIPTS.items():
        actual = hashlib.sha256(checked_source(project / relative)).hexdigest()
        need(actual == sha, 'versao de script C/C.1/C.2 divergiu do ensaio aprovado; revisar')

    # Garantias estaticas sobre o executavel PRINCIPAL; nao o iniciamos nem alteramos.
    main = checked_source(project / 'src/main.rs')
    bridge = checked_source(project / 'src/bridge.rs')
    cfg = checked_source(project / 'src/config.rs')
    mqtt = checked_source(project / 'src/mqtt.rs')
    need(b'bridge::start(' in main and b'mqtt::external_broker(cfg.mqtt_addr)' in main,
         'integracao da bridge com o executavel principal alterada')
    need(b'MqttOptions::new("rust-server-bridge-local", "localhost", broker.port())' in bridge and
         b'options.set_credentials("bridge", password)' in bridge and
         b'options.set_transport(Transport::tls_with_config(client_tls.into()))' in bridge,
         'bridge Rust divergiu do baseline')
    need(b'127.0.0.1:8883' in cfg and b'127.0.0.1:8883' in mqtt,
         'restricao de endereco do MQTT principal nao verificada')
    need(b'mqtt_bridge_password' in cfg and b'RUST_SERVER_MQTT_BRIDGE_PASSWORD' in cfg,
         'fonte da senha da bridge divergiu do baseline')


def passive_ports() -> dict[int, bool]:
    """Consulta apenas LISTEN (nao usa bind(), nao reinicia e nao sinaliza processos)."""
    try:
        result = subprocess.run(['ss', '-H', '-lnt'], capture_output=True, text=True,
                                timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise Block('consulta passiva de listeners indisponivel') from None
    need(result.returncode == 0, 'consulta passiva de listeners falhou')
    ports = {port: False for port in (8883, 8884, 8895, 8896)}
    for line in result.stdout.splitlines():
        items = line.split()
        if len(items) >= 4:
            tail = items[3].rsplit(':', 1)[-1]
            if tail.isdecimal() and int(tail) in ports:
                ports[int(tail)] = True
    return ports


def pending_counts(items: list[str]) -> dict[str, int]:
    return {
        'lab': sum(item.endswith(': lab') or item.startswith('confirmacao pendente (lab):')
                   for item in items),
        'bridge': sum(item.endswith(': bridge') or item.startswith('confirmacao pendente (bridge):')
                      for item in items),
        'device-sensor02': sum(item.endswith(': device-sensor02') or
                               item.startswith('confirmacao pendente (device-sensor02):') for item in items),
        'operacionais': sum(item.startswith('criterio operacional pendente:') for item in items),
    }


def verify(project: Path, snapshot: Path, backups: Path, private: Path,
           plugin: Path) -> tuple[list[str], dict[int, bool]]:
    c.verify_branch(project)
    # Reuso de validacoes existentes: snapshot e 20 arquivos originais sao somente leitura.
    fingerprint, mapping = c.baseline(snapshot, backups, project, private, plugin)
    need(set(mapping) == set(c.ACCOUNTS), 'politica de producao divergente')
    verified_sources(project)
    # Nao cria nem preenche modelo: e preciso que o cadastro privado existente seja valido.
    model = c.load_model(private)
    pendings, _ = c.validate_model(model, fingerprint)
    listeners = passive_ports()
    # A consolidação nao encerra processos alheios; portas temporarias ocupadas bloqueiam.
    need(not listeners[8895] and not listeners[8896],
         'listener temporario ativo; investigar sem encerrar processos externos')
    need(model['cutover_authorized'] is False, 'autorizacao de corte indevida')
    return pendings, listeners


def print_summary(pendings: list[str], listeners: dict[int, bool], *, verbose: bool) -> None:
    count = pending_counts(pendings)
    print('=== RUST-SERVER FASE 8.4.5.4-C — CONSOLIDACAO SOMENTE LEITURA ===')
    print('APROVADO: branch, fontes revisadas, politica, snapshot e cadastro privados verificados neste host.')
    print('REGISTRADO: C.1 — 47/47 testes, ensaio Rust/MQTT/TLS e rotacao/retorno isolados aprovados (logs do usuario).')
    print('REGISTRADO: C.2 — 55/55 testes, lab/sensor02, ACL, reconexao e rotacao/retorno isolados aprovados (logs do usuario).')
    print('REGISTRADO: snapshot de 20 arquivos e limpeza final das portas validados nos logs fornecidos.')
    for port in (8883, 8884, 8895, 8896):
        print(f'PORTA {port}: ' + ('LISTENER DETECTADO' if listeners[port] else 'SEM LISTENER'))
    print(f'CADASTRO: {len(pendings)} pendencias declarativas; '
          f'lab={count["lab"]}, bridge={count["bridge"]}, '
          f'sensor02={count["device-sensor02"]}, operacionais={count["operacionais"]}.')
    if verbose:
        for name in c.ACCOUNTS:
            print(f'PENDENTE: comprovar em producao a identidade e o Client ID efetivo de {name}, '
                  'sem substituir por IDs de ensaio.')
        print('PENDENTE: revisar estrategia de IDs dinamicos/por instancia para CLI lab e schema do cadastro C.')
        print('PENDENTE: canal autenticado de distribuicao, rotacao e rollback do lado do cliente.')
        print('PENDENTE: janela, responsaveis, monitores, gatilhos de aborto e snapshot final sob manutencao.')
    print('BLOQUEIOS EXTERNOS: auditoria de Seguranca, revisao Git e CI remoto; nao verificados por este comando.')
    print('LIMITE: os ensaios utilizaram contas/IDs/senhas temporarias; nao comprovam o cliente real lab/sensor02.')
    print('LIMITE: arquivos revisados e logs nao equivalem a aprovacao de operacao ou rollback real 8883.')
    readiness = ('C AGUARDANDO EVIDENCIAS' if pendings else
                 'C ELEGIVEL SOMENTE PARA REVISAO MANUAL EXTERNA')
    print(f'RESULTADO: C.1 e C.2 APROVADAS EM LABORATORIO; {readiness}; CORTE 8883 NAO AUTORIZADO.')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('consolidar', 'pendencias'))
    parser.add_argument('--snapshot', type=Path, required=True)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--backups-root', type=Path, default=Path.home() / 'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    a = parser.parse_args()
    try:
        project, snapshot, backups, private, plugin = (p.absolute() for p in
                  (a.project_root, a.snapshot, a.backups_root, a.private_root, a.plugin_path))
        pending, listeners = verify(project, snapshot, backups, private, plugin)
        print_summary(pending, listeners, verbose=(a.action == 'pendencias'))
        # 'consolidar' valida tecnicamente a consolidacao, sem declarar corte autorizado.
        # 'pendencias' preserva a convencao da fase C: status 3 se faltam evidencias.
        return 3 if a.action == 'pendencias' and pending else 0
    except (Block, c.Block, p2.Block, p3.Block, p4b.Block):
        print('BLOQUEIO: versoes, baseline, snapshot, branch, listeners ou cadastro nao validados; nada alterado.',
              file=sys.stderr)
        return 2
    except (OSError, ValueError, TypeError, UnicodeError):
        print('BLOQUEIO: verificacao falhou; detalhes de dados privados omitidos.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
