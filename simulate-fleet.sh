#!/usr/bin/env bash
set -euo pipefail

# ---------- Config (env overridable) ----------
BASE="${BASE:-http://localhost:8080}"
API_KEY="${API_KEY:?export API_KEY=...}"
PACKAGE_ID="${PACKAGE_ID:-1}"
VERSION="${VERSION:-1.0.0}"
FLEET_ID="${FLEET_ID:-1}"
COUNT="${COUNT:-20}"
SLEEP_MS="${SLEEP_MS:-120}"      # ms between devices
FAIL_CSV="${FAIL_CSV:-}"         # alternative to --fail

# Use a per-run, writable temp dir
DEFAULT_ROOT="${TMPDIR:-/tmp}"
RUN_TMP="$(mktemp -d "${DEFAULT_ROOT%/}/update-sim.XXXXXX")"

# Fallback to /tmp/update-sim for visibility if mktemp not available
if [[ -z "${RUN_TMP}" || ! -d "${RUN_TMP}" ]]; then
  RUN_TMP="/tmp/update-sim"
  if [[ -d "$RUN_TMP" ]]; then
    # If not writable (e.g., created by root), remove it
    if [[ ! -w "$RUN_TMP" ]]; then
      rm -rf "$RUN_TMP" 2>/dev/null || true
    fi
  fi
  mkdir -p "$RUN_TMP"
fi
chmod 700 "$RUN_TMP"

# ---------- Args ----------
FAIL_LIST=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --count)       COUNT="$2"; shift 2;;
    --fail)        FAIL_LIST="$2"; shift 2;;
    --sleep-ms)    SLEEP_MS="$2"; shift 2;;
    --fleet)       FLEET_ID="$2"; shift 2;;
    --package)     PACKAGE_ID="$2"; shift 2;;
    --version)     VERSION="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 1;;
  esac
done
[[ -n "${FAIL_CSV}" ]] && FAIL_LIST="${FAIL_CSV}"

# Build fail set
declare -A FAIL_SET
if [[ -n "$FAIL_LIST" ]]; then
  IFS=',' read -r -a _arr <<<"$FAIL_LIST"
  for x in "${_arr[@]}"; do
    x="${x//[[:space:]]/}"
    [[ -n "$x" ]] && FAIL_SET["$x"]=1
  done
fi

# Helpers
ms_sleep() {
  python3 - <<PY
import time
time.sleep(${1}/1000.0)
PY
}

json_get() {
  # json_get <file> <key>
  python3 - <<'PY' "$@"
import json,sys
if len(sys.argv) < 3:
    print("")  # be graceful
    raise SystemExit(0)
p=sys.argv[1]; k=sys.argv[2]
try:
    with open(p,'rb') as f:
        data=json.load(f)
    v=data.get(k, "")
    if isinstance(v,(int,float)):
        print(v)
    elif isinstance(v,str):
        print(v.strip())
    else:
        print("")
except Exception:
    print("")
PY
}

say_cfg() {
  echo "== CONFIG =="
  echo "BASE=$BASE"
  echo "PACKAGE_ID=$PACKAGE_ID VERSION=$VERSION"
  echo "FLEET_ID=$FLEET_ID COUNT=$COUNT"
  echo "FAIL=[${FAIL_LIST:-none}] SLEEP_MS=$SLEEP_MS"
  echo "TMP=$RUN_TMP"
  echo
}
say_cfg

# ---------- Loop over devices ----------
echo "== Registering & exercising devices =="
for ((i=1;i<=COUNT;i++)); do
  host="agent-$i"
  echo "-- device#$i register $host"

  reg_json="$RUN_TMP/reg_$i.json"
  http_code=$(curl -sS -o "$reg_json" -w "%{http_code}" \
    -X POST "$BASE/api/agents/register" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"hostname\":\"$host\",\"fleetId\":$FLEET_ID}")
  echo "HTTP $http_code  POST /api/agents/register"
  echo -n "BODY: "; cat "$reg_json" || true
  if [[ "$http_code" != "200" ]]; then
    echo "ERROR: register failed (device#$i)" >&2
    continue
  fi

  device_id="$(json_get "$reg_json" deviceId || echo "")"
  if [[ -z "$device_id" ]]; then
    echo "ERROR: register returned no deviceId (device#$i)" >&2
    continue
  fi
  echo "deviceId=$device_id"

  # Heartbeat
  hb_json="$RUN_TMP/hb_$i.json"
  http_code=$(curl -sS -o "$hb_json" -w "%{http_code}" \
    -X POST "$BASE/api/agents/heartbeat" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"deviceId\":$device_id,\"agentVersion\":\"1.2.$i\",\"osVersion\":\"Windows 11\"}")
  echo "HTTP $http_code  POST /api/agents/heartbeat"
  echo -n "BODY: "; cat "$hb_json" || true

  # Download artifact to file (never into a substitution)
  bin_path="$RUN_TMP/update_$i.bin"
  http_code=$(curl -sS -o "$bin_path" -w "%{http_code}" \
    -H "X-API-Key: $API_KEY" \
    "$BASE/api/updates/$PACKAGE_ID/$VERSION")
  echo "HTTP $http_code  GET /api/updates/$PACKAGE_ID/$VERSION"

  # Report install result
  if [[ -n "${FAIL_SET[$i]:-}" ]]; then
    status="failed"
    echo "   device#$i report FAILED"
  else
    status="succeeded"
    echo "   device#$i report SUCCESS"
  fi
  res_json="$RUN_TMP/result_$i.json"
  http_code=$(curl -sS -o "$res_json" -w "%{http_code}" \
    -X POST "$BASE/api/agents/install-results" \
    -H "X-API-Key: $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"deviceId\":$device_id,\"packageId\":$PACKAGE_ID,\"version\":\"$VERSION\",\"status\":\"$status\"}")
  echo "HTTP $http_code  POST /api/agents/install-results"
  echo -n "BODY: "; cat "$res_json" || true

  ms_sleep "$SLEEP_MS"
  echo
done

echo "== SUMMARY =="
echo "Intended failures: ${FAIL_LIST:-none}"
echo "Done."

