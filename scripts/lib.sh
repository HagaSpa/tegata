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

CALLBACK="http://localhost:9999/callback"
CHALLENGE="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
VERIFIER="dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

get_tokens() {
  local query="client_id=tegata-sample&redirect_uri=${CALLBACK}&response_type=code&scope=$1&state=smoke-state&nonce=smoke-nonce&code_challenge=${CHALLENGE}&code_challenge_method=S256"
  local id code
  id=$(curl -fsS "$BASE/authorize?$query" | sed -n 's/.*name="id" value="\([^"]*\)".*/\1/p')
  code=$(curl -sS -o /dev/null -w '%{redirect_url}' -d "id=$id&username=username&password=password&action=approve" "$BASE/login" | sed -n 's/.*code=\([^&]*\).*/\1/p')
  curl -sS -u tegata-sample:dummy-secret \
    -d "grant_type=authorization_code&code=$code&redirect_uri=$CALLBACK&code_verifier=$VERIFIER" \
    "$BASE/token"
}

require_jq() {
  if ! command -v jq >/dev/null; then
    echo "jq is required" >&2
    exit 1
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
