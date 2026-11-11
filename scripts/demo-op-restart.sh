#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
source scripts/lib.sh

RS="http://localhost:9000"

require_jq
for port in 8080 9000; do
  if curl -s -o /dev/null "localhost:$port"; then
    echo "port $port is already in use (stop it first, e.g. mise dev:stop or mise conformance:stop)" >&2
    exit 1
  fi
done

tmp=$(mktemp -d)
op_pid=""
rs_pid=""
cleanup() {
  if [[ -n $rs_pid ]]; then kill "$rs_pid" 2>/dev/null || true; fi
  if [[ -n $op_pid ]]; then kill "$op_pid" 2>/dev/null || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT

wait_for() {
  for _ in $(seq 1 50); do
    if curl -s -o /dev/null "$1"; then
      return 0
    fi
    sleep 0.2
  done
  echo "timed out waiting for $1" >&2
  exit 1
}

start_op() {
  "$tmp/op" >/dev/null 2>&1 &
  op_pid=$!
  wait_for "$BASE/"
}

stop_op() {
  kill "$op_pid"
  wait "$op_pid" 2>/dev/null || true
}

kid_of() {
  jq -rR 'split(".")[0] | gsub("-";"+") | gsub("_";"/") | @base64d | fromjson | .kid[:8]' <<<"$1"
}

jwks_kid() {
  curl -fsS "$BASE/.well-known/jwks.json" | jq -r '.keys[0].kid[:8]'
}

token() {
  get_tokens "openid%20notes.read" | jq -r .access_token
}

send() {
  local label=$1 tok=$2 want=$3 why=$4 got mark
  got=$(curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $tok" "$RS/notes")
  mark="OK"
  if [[ $got != "$want" ]]; then
    mark="NG"
    failures=$((failures + 1))
  fi
  printf '   [%s] %s → %s（期待 %s）: %s\n' "$mark" "$label" "$got" "$want" "$why"
}

echo "== 準備: OP と RS をビルドして起動"
go build -o "$tmp/op" ./cmd/op
go build -o "$tmp/rs" ./cmd/rs
start_op
"$tmp/rs" >/dev/null 2>&1 &
rs_pid=$!
wait_for "$RS/notes"
echo "   OP の JWKS の kid: $(jwks_kid)"

echo
echo "== 1. OP の再起動前"
old=$(token)
echo "   古いトークンを取得（kid: $(kid_of "$old")）"
send "古いトークン" "$old" 200 "RS が初めて JWKS を取りに行き、この kid の公開鍵を覚える"

echo
echo "== 2. OP だけ再起動する（鍵が作り直される。RS はそのまま）"
stop_op
start_op
echo "   OP の JWKS の kid: $(jwks_kid)"
new=$(token)
echo "   新しいトークンを取得（kid: $(kid_of "$new")）"
send "古いトークン" "$old" 200 "RS のキャッシュに古い公開鍵が残っていて、署名も本物"
send "新しいトークン" "$new" 401 "未知の kid だが、前回の取得から 30 秒経っていないので取り直さない"

echo
echo "== 3. 30 秒待つ"
for left in 30 20 10; do
  echo "   残り ${left} 秒"
  sleep 10
done
sleep 1
send "新しいトークン" "$new" 200 "未知の kid なので JWKS を取り直し、新しい公開鍵を覚える"
send "古いトークン" "$old" 401 "取り直しでキャッシュが入れ替わり、古い kid が消えた"

echo
finish
