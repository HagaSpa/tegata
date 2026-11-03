#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

RS="${RS:-http://localhost:9000}"

require_jq
require_server
if ! curl -sS -o /dev/null "$RS/notes"; then
  echo "resource server is not reachable at $RS (start it with: mise serve-rs)" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

call() {
  code=$(curl -sS -D "$tmp/headers" -o "$tmp/body" -w '%{http_code}' "$@" "$RS/notes")
  challenge=$(tr -d '\r' <"$tmp/headers" | sed -n 's/^[Ww][Ww][Ww]-[Aa]uthenticate: //p')
  body=$(cat "$tmp/body")
}

post() {
  call -H "Authorization: Bearer $1" -H "Content-Type: application/json" -d "$2"
}

read_res=$(get_tokens "openid%20notes.read")
read_at=$(jq -r .access_token <<<"$read_res")
read_it=$(jq -r .id_token <<<"$read_res")
write_at=$(get_tokens "openid%20notes.read%20notes.write" | jq -r .access_token)
openid_at=$(get_tokens "openid" | jq -r .access_token)

call
check_eq "ヘッダなし: 401" "$code" 401
check_eq "ヘッダなし: WWW-Authenticate は Bearer だけ" "$challenge" "Bearer"

call -H "Authorization: Bearer $read_at"
check_eq "notes.read: GET は 200" "$code" 200
check_eq "notes.read: GET は配列を返す" "$(jq -r type <<<"$body")" "array"

post "$read_at" '{"text":"smoke"}'
check_eq "notes.read: POST は 403" "$code" 403
check_eq "notes.read: POST は insufficient_scope" "$challenge" 'Bearer error="insufficient_scope", scope="notes.write"'

call -H "Authorization: Bearer $read_it"
check_eq "ID トークン: 401" "$code" 401
check_eq "ID トークン: invalid_token" "$challenge" 'Bearer error="invalid_token"'

call -H "Authorization: Bearer $openid_at"
check_eq "scope=openid のアクセストークン（aud が userinfo だけ）: 401" "$code" 401
check_eq "scope=openid のアクセストークン: invalid_token" "$challenge" 'Bearer error="invalid_token"'

text="smoke-$RANDOM"
post "$write_at" "{\"text\":\"$text\"}"
check_eq "notes.write: POST は 201" "$code" 201
check_eq "notes.write: POST は作ったノートを返す" "$body" "{\"text\":\"$text\"}"

call -H "Authorization: Bearer $read_at"
check_eq "POST したノートが GET に出る" "$(jq --arg t "$text" 'any(.[]; .text == $t)' <<<"$body")" true

post "$write_at" '{"text":""}'
check_eq "notes.write: text が空なら 400" "$code" 400

finish
