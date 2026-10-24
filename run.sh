#!/usr/bin/env sh
# Personal assistant launcher (macOS/Linux). Same commands as run.ps1; keeps caches and temp files in .cache/.
ROOT="$(cd "$(dirname "$0")" && pwd)"
PY="$ROOT/.venv/bin/python"
export PYTHONPYCACHEPREFIX="$ROOT/.cache/pycache"
export PLAYWRIGHT_BROWSERS_PATH="$ROOT/.cache/ms-playwright"
mkdir -p "$ROOT/.cache/tmp"
export TMPDIR="$ROOT/.cache/tmp" TEMP="$ROOT/.cache/tmp" TMP="$ROOT/.cache/tmp"
cd "$ROOT" || exit 1
cmd="${1:-help}"; [ $# -gt 0 ] && shift
case "$cmd" in
  init)            exec "$PY" -m assistant.cli --init "$@" ;;
  chat)            exec "$PY" -m assistant.cli "$@" ;;
  test)            exec "$PY" -m pytest -q "$@" ;;
  scenarios)       exec "$PY" -m assistant.harness.run_scenarios "$@" ;;
  install-browser) exec "$PY" -m playwright install chromium ;;
  guide)           exec "$PY" -m assistant.guide --from-launcher "$@" ;;
  *) echo "usage: ./run.sh init|chat|test|scenarios|install-browser|guide" ;;
esac
