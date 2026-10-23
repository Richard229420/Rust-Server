#!/usr/bin/env bash
# Fase 8.2: substituir auditoria antiga baseada só em SUBACK.
set -euo pipefail
exec bash "$(dirname "$0")/test_phase8_2_acl.sh"
