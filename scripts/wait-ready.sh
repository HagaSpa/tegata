#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

RS="${RS:-http://localhost:9000}"
TIMEOUT="${TIMEOUT:-60}"

wait_for() {
  local url=$1 elapsed=0
  until curl -s -o /dev/null "$url"; do
    if ((elapsed >= TIMEOUT)); then
      echo "timed out waiting for $url" >&2
      exit 1
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
}

wait_for "$BASE/.well-known/openid-configuration"
wait_for "$RS/notes"
echo "tegata ($BASE) and the RS ($RS) are ready"
