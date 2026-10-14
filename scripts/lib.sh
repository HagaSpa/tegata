BASE="${BASE:-http://localhost:8080}"

failures=0

check() {
  local name=$1 got=$2 pattern=$3
  if [[ $got =~ $pattern ]]; then
    printf 'PASS  %s\n' "$name"
  else
    printf 'FAIL  %s\n      got:  %s\n      want: %s\n' "$name" "$got" "$pattern"
    failures=$((failures + 1))
  fi
}

check_eq() {
  local name=$1 got=$2 want=$3
  if [[ $got == "$want" ]]; then
    printf 'PASS  %s\n' "$name"
  else
    printf 'FAIL  %s\n      got:  %s\n      want: %s\n' "$name" "$got" "$want"
    failures=$((failures + 1))
  fi
}

require_server() {
  if ! curl -fsS -o /dev/null "$BASE/"; then
    echo "server is not reachable at $BASE (start it with: mise serve)" >&2
    exit 1
  fi
}

finish() {
  if ((failures > 0)); then
    echo "$failures check(s) failed" >&2
    exit 1
  fi
  echo "all checks passed"
}
