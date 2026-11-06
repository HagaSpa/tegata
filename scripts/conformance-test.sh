#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

SUITE="${SUITE:-https://localhost.emobix.co.uk:8443}"
ISSUER="http://tegata.localhost:8080"
CONFIG="$(dirname "$0")/conformance-config.json"
TIMEOUT="${TIMEOUT:-120}"
BASIC_VARIANT='{"server_metadata":"discovery","client_registration":"static_client"}'

usage() {
  echo "usage: $0 [basic [module...] | config]" >&2
  exit 1
}

api() {
  curl -fsSk "$@"
}

first_problem() {
  api "$SUITE/api/log/$1" | jq -r '
    [.[] | select(.result == "FAILURE")] + [.[] | select(.result == "WARNING")] | first
    | if . == null then "" else
        "\(.src): \(.msg)"
        + (if .error then " (error=\(.error)" + (if .error_description then ", error_description=\(.error_description)" else "" end) + ")" else "" end)
      end'
}

run_module() {
  local plan=$1 module=$2 id info status result elapsed=0 problem
  id=$(api -X POST --url-query "test=$module" --url-query "plan=$plan" "$SUITE/api/runner" | jq -r .id)
  while :; do
    info=$(api "$SUITE/api/info/$id")
    status=$(jq -r .status <<<"$info")
    result=$(jq -r '.result // ""' <<<"$info")
    if [[ $status == FINISHED || $status == INTERRUPTED ]]; then
      break
    fi
    if ((elapsed >= TIMEOUT)); then
      api -X DELETE -o /dev/null "$SUITE/api/runner/$id" || true
      result="TIMEOUT($status)"
      break
    fi
    sleep 1
    elapsed=$((elapsed + 1))
  done
  if [[ -z $result ]]; then
    result=$status
  fi
  printf '%-16s %s\n' "$result" "$module"
  if [[ $result != PASSED ]]; then
    problem=$(first_problem "$id")
    if [[ -n $problem ]]; then
      printf '%-16s   %s\n' "" "$problem"
    fi
    printf '%-16s   %s/log-detail.html?log=%s\n' "" "$SUITE" "$id"
  fi
  results+=("$result")
}

run_plan() {
  local label=$1 name=$2 variant=$3
  shift 3
  local args=(--url-query "planName=$name")
  if [[ -n $variant ]]; then
    args+=(--url-query "variant=$variant")
  fi
  local plan id module
  local modules=()
  plan=$(api -X POST -H 'Content-Type: application/json' --data @"$CONFIG" "${args[@]}" "$SUITE/api/plan")
  id=$(jq -r .id <<<"$plan")
  if (($# > 0)); then
    modules=("$@")
  else
    while IFS= read -r module; do
      modules+=("$module")
    done < <(jq -r '.modules[].testModule' <<<"$plan")
  fi
  echo "== $label ($SUITE/plan-detail.html?plan=$id)"
  for module in "${modules[@]}"; do
    run_module "$id" "$module"
  done
}

require_jq

if ! curl -fsSk -o /dev/null "$SUITE/api/runner/available"; then
  echo "conformance suite is not reachable at $SUITE (start it with: mise conformance)" >&2
  exit 1
fi
if ! curl -fsS -o /dev/null "$ISSUER/.well-known/openid-configuration"; then
  echo "tegata is not reachable at $ISSUER (start it with: mise conformance)" >&2
  exit 1
fi

results=()
case "${1:-all}" in
  all)
    run_plan "Basic OP" oidcc-basic-certification-test-plan "$BASIC_VARIANT"
    run_plan "Config OP" oidcc-config-certification-test-plan ""
    ;;
  basic)
    shift
    run_plan "Basic OP" oidcc-basic-certification-test-plan "$BASIC_VARIANT" "$@"
    ;;
  config)
    run_plan "Config OP" oidcc-config-certification-test-plan ""
    ;;
  *)
    usage
    ;;
esac

echo "== summary"
printf '%s\n' "${results[@]}" | sort | uniq -c
