#!/usr/bin/env python3
"""Fase 8.4.5.4-C.3: saneamento verificavel SEM CORTE.

Acoes:
  auditar               audita snapshot/cadastro e exibe pendencias (somente leitura)
  registrar-bridge-fonte registra SOMENTE 3 campos de evidencia estatica da bridge
  roteiro               mostra requisitos concretos para evidencias restantes

NUNCA marca confirmacao em producao, nunca abre conexoes MQTT, nunca altera
8883/8884, snapshot, credenciais, Git, CI ou configuracao Rust.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile

import fase8_4_5_4c_prontidao_corte as c
import fase8_4_5_4c_consolidar as cons
import fase8_4_5_2_preparar as p2

BRIDGE_ID = 'rust-server-bridge-local'
BRIDGE_REFERENCE = 'src-bridge-rs-92-94'
BRIDGE_SOURCE_KIND = 'application-code'
ALLOWED_ACTIONS = ('auditar', 'registrar-bridge-fonte', 'roteiro')


class Block(Exception):
    """Nao divulga informacoes privadas."""


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise Block(message)


def verify_bridge_source(project: Path) -> None:
    # Respeita os pins das versoes C/C1/C2 revisadas na consolidacao anterior.
    cons.verified_sources(project)
    source = cons.checked_source(project / 'src/bridge.rs')
    ensure(b'MqttOptions::new("rust-server-bridge-local", "localhost", broker.port())' in source,
           'ID da bridge nao coincide com codigo revisado')
    ensure(b'options.set_credentials("bridge", password)' in source,
           'usuario MQTT da bridge nao coincide com codigo revisado')


def reviewed_model(model: dict, fingerprint: str) -> dict:
    """Atualiza exclusivamente os 3 campos comprovados pela fonte Rust.

    Nao altera flags de confirmacao: codigo fonte nao prova runtime de producao.
    """
    c.validate_model(model, fingerprint)
    clone = copy.deepcopy(model)
    targets = [x for x in clone['identities'] if x['username'] == 'bridge']
    ensure(len(targets) == 1, 'identidade bridge ausente ou duplicada')
    entry = targets[0]
    ensure(entry['client_id_confirmado'] is False,
           'cadastro ja declara confirmacao operacional; revisao humana necessaria')
    expected = {
        'client_id': BRIDGE_ID,
        'evidence_kind': BRIDGE_SOURCE_KIND,
        'evidence_ref': BRIDGE_REFERENCE,
    }
    for field, value in expected.items():
        ensure(entry[field] in ('', value), 'evidencia previa diverge; revisao humana necessaria')
        entry[field] = value
    ensure(clone['cutover_authorized'] is False, 'autorizacao de corte indevida')
    c.validate_model(clone, fingerprint)
    return clone


def secured_original(path: Path) -> tuple[bytes, os.stat_result]:
    """Protege contra symlinks/hardlinks/permissoes incorretas."""
    try:
        s = path.lstat()
        ensure(stat.S_ISREG(s.st_mode) and not path.is_symlink() and
               s.st_nlink == 1 and s.st_uid == os.geteuid() and
               stat.S_IMODE(s.st_mode) == 0o600 and 0 < s.st_size <= 32768,
               'cadastro privado inseguro')
        contents = p2.check_regular(path, private=True, limit=32768)
        return contents, s
    except (OSError, p2.Block):
        raise Block('cadastro privado ausente ou inseguro') from None


def atomic_save_model(path: Path, original_data: bytes,
                      original_stat: os.stat_result, model: dict) -> bool:
    """Grava somente mediante acao explicita; protege outras alteracoes do cadastro."""
    updated = (json.dumps(model, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    ensure(len(updated) <= 32768, 'cadastro acima do limite permitido')
    if original_data == updated:
        return False
    directory = path.parent
    tmp_path: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix='.cadastro-c3-', suffix='.tmp', dir=directory)
        tmp_path = Path(name)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(updated)
            out.flush()
            os.fsync(out.fileno())
        # Se houver mudanca de inode, conteudo ou metadados relevantes, abortar.
        before, s = secured_original(path)
        ensure(s.st_ino == original_stat.st_ino and
               s.st_dev == original_stat.st_dev and
               s.st_mtime_ns == original_stat.st_mtime_ns and
               hashlib.sha256(before).digest() == hashlib.sha256(original_data).digest(),
               'cadastro foi alterado durante a operacao')
        os.replace(tmp_path, path)
        tmp_path = None
        dir_fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        secured_original(path)
        return True
    except (OSError, p2.Block):
        raise Block('gravacao privada falhou; conferir permissao e integridade') from None
    finally:
        if tmp_path is not None:
            try:
                tmp_path.unlink(missing_ok=True)
            except OSError:
                pass


def summarize(pending: list[str]) -> None:
    counts = cons.pending_counts(pending)
    print('=== 8.4.5.4-C.3: EVIDENCIAS SEM CORTE ===')
    print(f'PENDENCIAS DECLARATIVAS: {len(pending)} '
          f'(lab={counts["lab"]}, bridge={counts["bridge"]}, '
          f'sensor02={counts["device-sensor02"]}, operacionais={counts["operacionais"]}).')
    print('BRIDGE: fonte Rust identificada; confirmacao do processo real permanece obrigatoria.')
    print('LAB: modelo C-v1 exige ID unico, mas o ensaio C.2 usou IDs CLI variaveis; nao inventar ID.')
    print('SENSOR02: Client ID no dispositivo/servico real nao foi comprovado.')
    print('EXTERNOS: Git/CI e Seguranca nao sao aprovados por este comando.')
    print('RESULTADO: cadastro em revisao; CORTE 8883 NAO AUTORIZADO.')


def instructions() -> None:
    print('=== ROTEIRO PARA FECHAR EVIDENCIAS REAIS — SEM ALTERAR BROKERS ===')
    print('1 BRIDGE: confirmar unidade/processo que inicia main.rs, endereco MQTT efetivo e ID')
    print('  rust-server-bridge-local; guardar referencia de configuracao sem senhas.')
    print('2 LAB: classificar cada instancia CLI real; se IDs dinamicos, nao preencher')
    print('  client_id do cadastro C-v1; aprovar revisao de schema/politica com Seguranca.')
    print('  Alternativa: identidades dedicadas por instancia com IDs fixos e ACL minima.')
    print('3 SENSOR02: identificar firmware/servico/config efetiva e Client ID unico;')
    print('  testar reconfiguracao e retorno do cliente REAL fora de producao.')
    print('4 SEGREDOS: definir cofre, canal autenticado, custodia, rotacao e retencao')
    print('  controlada da credencial legada ate fim da janela de reversao.')
    print('5 ROLLBACK: comprovar retorno de configuracao e reconexao de CADA cliente,')
    print('  nao apenas restauracao do broker em 8896.')
    print('6 OPERACAO: definir responsaveis, janela, monitoramento, criterios de aborto,')
    print('  snapshot FINAL sob manutencao e validacao de hashes antes de eventual corte.')
    print('7 EXTERNOS: enviar evidencias redigidas a Seguranca e Git/CI em seus chats;')
    print('  receber decisoes formais antes de planejar 8.4.5.5.')
    print('NAO EXECUTAR: mosquitto, git add/commit/push, atualizacao de credenciais ou CORTE 8883.')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=ALLOWED_ACTIONS)
    parser.add_argument('--snapshot', required=True, type=Path)
    parser.add_argument('--project-root', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--private-root', type=Path, default=Path.home() / '.config/rust-server')
    parser.add_argument('--backups-root', type=Path,
                        default=Path.home() / 'server_backups/fase8_4_5_2')
    parser.add_argument('--plugin-path', type=Path, default=p2.PLUGIN)
    args = parser.parse_args(argv)
    try:
        project, snapshot, private, backups, plugin = (p.absolute() for p in
                  (args.project_root, args.snapshot, args.private_root,
                   args.backups_root, args.plugin_path))
        c.verify_branch(project)
        fingerprint, _ = c.baseline(snapshot, backups, project, private, plugin)
        verify_bridge_source(project)
        folder = c.private_folder(private, create=False)
        model_path = folder / c.FILENAME
        raw, original_stat = secured_original(model_path)
        model = c.load_model(private)
        pendings, _ = c.validate_model(model, fingerprint)
        if args.action == 'roteiro':
            instructions()
        elif args.action == 'auditar':
            summarize(pendings)
        else:
            new_model = reviewed_model(model, fingerprint)
            changed = atomic_save_model(model_path, raw, original_stat, new_model)
            new_pendings, _ = c.validate_model(c.load_model(private), fingerprint)
            print('APROVADO: evidencia ESTATICA da bridge registrada.' if changed else
                  'APROVADO: evidencia estatica da bridge ja estava registrada.')
            print('NAO COMPROVADO: execucao real de bridge nem troca de credencial produtiva.')
            summarize(new_pendings)
        return 0
    except (Block, c.Block, cons.Block, p2.Block, ValueError, TypeError, OSError):
        print('BLOQUEIO: baseline, fonte, snapshot ou cadastro nao validado. '
              'Nenhum broker alterado; corte 8883 NAO AUTORIZADO.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
