#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

SUITE="${SUITE:-https://localhost.emobix.co.uk:8443}"
ISSUER="${ISSUER:-http://tegata.localhost:8080}"

require_jq

if ! curl -fsSk -o /dev/null "$SUITE/api/runner/available"; then
  echo "conformance suite is not reachable at $SUITE (start it with: mise conformance)" >&2
  exit 1
fi
if ! curl -fsS -o /dev/null "$ISSUER/.well-known/openid-configuration"; then
  echo "tegata is not reachable at $ISSUER (start it with: mise serve-conformance)" >&2
  exit 1
fi

config=$(jq -n --arg issuer "$ISSUER" '{
  alias: "tegata",
  description: "tegata local",
  server: { discoveryUrl: ($issuer + "/.well-known/openid-configuration") },
  client: { client_id: "conformance", client_secret: "conformance-secret" }
}')

create_plan() {
  local label=$1 name=$2 variant=${3:-}
  local args=(--url-query "planName=$name")
  [[ -n $variant ]] && args+=(--url-query "variant=$variant")
  local id
  id=$(curl -fsSk -X POST -H 'Content-Type: application/json' --data "$config" "${args[@]}" "$SUITE/api/plan" | jq -r .id)
  printf '%-10s %s/plan-detail.html?plan=%s\n' "$label" "$SUITE" "$id"
}

create_plan "Basic OP" oidcc-basic-certification-test-plan '{"server_metadata":"discovery","client_registration":"static_client"}'
create_plan "Config OP" oidcc-config-certification-test-plan
