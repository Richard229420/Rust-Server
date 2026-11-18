#!/usr/bin/env python3
"""Regressao fase 8.4.4: before -> apply -> after. Sem alteracoes em --before/--after."""
from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

BASE = Path(__file__).resolve().parents[1]
SCRIPTS = BASE / 'scripts'
TESTS = BASE / 'tests'


def step(label, argv, *, cwd=BASE):
    print(f'\n=== {label} ===', flush=True)
    result = subprocess.run(argv, cwd=cwd, check=False)
    if result.returncode != 0:
        raise RuntimeError(f'{label}: falhou (rc={result.returncode}); nao avancar')
    print(f'APROVADO: {label}', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stage', choices=['before', 'after', 'offline'])
    args = parser.parse_args()
    py = sys.executable
    offline = [
        ('Python Fase 8.3', [py, str(TESTS / 'test_phase8_3_manager.py')]),
        ('Python Fase 8.4.1', [py, str(TESTS / 'test_fase8_4_1_snapshot.py')]),
        ('Python Fase 8.4.2', [py, str(TESTS / 'test_fase8_4_2_lab.py')]),
        ('Python Fase 8.4.4', [py, str(TESTS / 'test_fase8_4_4_online.py')]),
    ]
    for label, cmd in offline:
        step(label, cmd)
    step('Sintaxe Python', [py, '-m', 'py_compile',
         str(SCRIPTS / 'fase8_4_4_online.py'), str(SCRIPTS / 'regressao_fase8_4_4.py'),
         str(TESTS / 'test_fase8_4_4_online.py')])
    step('Formato Rust', ['cargo', 'fmt', '--check'])
    step('Cargo check', ['cargo', 'check', '--offline', '--locked', '--all-targets'])
    step('Cargo test', ['cargo', 'test', '--offline', '--locked', '--all-targets'])
    if args.stage == 'before':
        step('MQTT 8.4.2 (ambos sensores ativos)', [py, str(SCRIPTS / 'test_fase8_4_2_isolamento.py')])
        step('Preflight 8.4.4', [py, str(SCRIPTS / 'fase8_4_4_online.py'), 'preflight'])
    elif args.stage == 'after':
        step('MQTT 8.4.4 (sensor01 desabilitado)', [py, str(SCRIPTS / 'fase8_4_4_online.py'), 'after'])
    print(f'\nAPROVADO: regressao {args.stage}. Testes da porta 8883 dependem dos servicos originais.')


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError) as exc:
        print('REPROVADO:', exc, file=sys.stderr)
        sys.exit(1)
