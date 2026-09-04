#!/usr/bin/env bash
# SOC Pipeline - Technitium DNS feed (cron-safe, self-contained).
#
# One pull cycle every 15 min:
#   collector (read-only incremental pull from all Technitium servers) ->
#   deliver NEW events to Graylog DNS input (GELF/TCP :12202) + Wazuh DNS localfile.
#
# Read-only against Technitium (logs/query API). Per-server timestamp state in
# collector/.dns_state.json means each run only ships new records. Emits one-line
# JSON status to stdout + /var/log/dns-pull.log.
#
# Public, portable wrapper.
set -u

ENVF="${SOC_ENV_FILE:-$HOME/.config/soc-pipeline/env}"
REPO="${SOC_PIPELINE_ROOT:-$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)}"
PYBIN="${PYTHON_BIN:-/usr/bin/python3}"           # stdlib-only collector; no venv needed
LOG="${DNS_PULL_LOG:-$HOME/.local/state/soc-pipeline/dns-pull.log}"

status() {  # status <ok|error> <message> [extra-json]
  local st="$1" msg="$2" extra="${3:-}"
  local ts; ts=$(date -u +%FT%TZ)
  local line="{\"job\":\"dns-pull\",\"time\":\"$ts\",\"status\":\"$st\",\"message\":\"$msg\"${extra:+,$extra}}"
  echo "$line"; mkdir -p "$(dirname "$LOG")"; echo "$line" >> "$LOG"
}

[ -f "$ENVF" ] || { status error "env not found: $ENVF"; exit 1; }
[ -x "$PYBIN" ] || PYBIN=$(command -v python3)

OUT=$(cd "$REPO" && "$PYBIN" collector/dns_pipeline.py \
        --graylog-port 12202 \
        --wazuh-path /var/ossec/logs/dns/queries.jsonl \
        --lookback-min 20 2>&1)
RC=$?

# parse compact counters from the pipeline output
COLLECTED=$(printf '%s\n' "$OUT" | grep -oE 'collected [0-9]+' | grep -oE '[0-9]+' | head -1)
DELIV=$(printf '%s\n' "$OUT" | grep -oE 'delivered [0-9]+' | grep -oE '[0-9]+' | head -1)

if [ "$RC" -ne 0 ]; then
  status error "pipeline exited $RC" "\"tail\":\"$(printf '%s' "$OUT" | tail -1 | tr '\"' \' | cut -c1-160)\""
  exit "$RC"
fi
status ok "dns pull complete" "\"collected\":${COLLECTED:-0},\"delivered\":${DELIV:-0}"
