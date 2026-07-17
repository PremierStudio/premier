#!/usr/bin/env bash
# Emit a Premier agent event to the active local collector.
# Prefer `premier emit` when the binary is on PATH; this script is a pure-shell fallback.
set -euo pipefail

if [[ -z "${PREMIER_COLLECTOR_URL:-}" || -z "${PREMIER_COLLECTOR_TOKEN:-}" ]]; then
  echo "Premier collector is not active. Run under: premier record -- <command>" >&2
  exit 1
fi

if command -v premier >/dev/null 2>&1; then
  if [[ $# -eq 0 || "$1" == "-" ]]; then
    exec premier emit --json -
  fi
  # If first arg looks like JSON, pass through; otherwise forward flags.
  if [[ "$1" == \{* ]]; then
    exec premier emit --json "$1"
  fi
  exec premier emit "$@"
fi

if [[ $# -eq 0 || "$1" == "-" ]]; then
  BODY="$(cat)"
elif [[ "$1" == \{* ]]; then
  BODY="$1"
else
  echo "usage: premier-emit.sh '{\"kind\":\"agent.spawn\",...}'" >&2
  echo "   or: echo '{...}' | premier-emit.sh -" >&2
  echo "   or: install premier and use: premier emit --kind ..." >&2
  exit 1
fi

curl -sS -X POST "$PREMIER_COLLECTOR_URL" \
  -H "Authorization: Bearer $PREMIER_COLLECTOR_TOKEN" \
  -H "Content-Type: application/json" \
  --data-raw "$BODY"
echo
