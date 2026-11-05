#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

SAMPLE="tegata-sample:dummy-secret"
OTHER="tegata-rp:rp-secret"

require_jq
require_server

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

call() {
  local client=$1 path=$2
  shift 2
  code=$(curl -sS -o "$tmp/body" -w '%{http_code}' -u "$client" "$@" "$BASE$path")
  body=$(cat "$tmp/body")
  error=$(jq -r '.error // empty' <<<"$body" 2>/dev/null || true)
}

refresh() {
  call "${2:-$SAMPLE}" /token -d grant_type=refresh_token --data-urlencode "refresh_token=$1"
}

revoke() {
  call "${2:-$SAMPLE}" /revoke --data-urlencode "token=$1"
}

login() {
  get_tokens "openid%20offline_access" | jq -r .refresh_token
}

discovery=$(curl -fsS "$BASE/.well-known/openid-configuration")
check_eq "Discovery: grant_types_supported" "$(jq -c .grant_types_supported <<<"$discovery")" '["authorization_code","refresh_token"]'
check_eq "Discovery: revocation_endpoint" "$(jq -r .revocation_endpoint <<<"$discovery")" "$BASE/revoke"
check_eq "Discovery: revocation_endpoint_auth_methods_supported" \
  "$(jq -c .revocation_endpoint_auth_methods_supported <<<"$discovery")" '["client_secret_post","client_secret_basic"]'

check_eq "offline_access なし: refresh_token は返らない" "$(get_tokens "openid" | jq -c 'has("refresh_token")')" false
rt1=$(login)
check "offline_access あり: refresh_token が返る" "$rt1" '^[A-Za-z0-9_-]{43}$'

refresh "$rt1"
check_eq "refresh: 200" "$code" 200
rt2=$(jq -r .refresh_token <<<"$body")
at2=$(jq -r .access_token <<<"$body")
check_eq "refresh: id_token は含まない" "$(jq -c 'has("id_token")' <<<"$body")" false
check_eq "refresh: scope は元のまま" "$(jq -r .scope <<<"$body")" "openid offline_access"
check "refresh: 新しい refresh_token が返る" "$rt2" '^[A-Za-z0-9_-]{43}$'
check_eq "refresh: refresh_token は前と違う値になる" "$([[ $rt2 == "$rt1" ]] && echo same || echo changed)" changed
check_eq "refresh: 新しいアクセストークンで userinfo が 200" \
  "$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $at2" "$BASE/userinfo")" 200

refresh "$rt1"
check_eq "再利用: 使用済みの rt1 は invalid_grant" "$code $error" "400 invalid_grant"
refresh "$rt2"
check_eq "再利用: 同じ系列の rt2 も invalid_grant" "$code $error" "400 invalid_grant"

rt=$(login)
refresh "$rt" "$OTHER"
check_eq "別クライアント: refresh は invalid_grant" "$code $error" "400 invalid_grant"
revoke "$rt" "$OTHER"
check_eq "別クライアント: revoke は 200" "$code" 200
refresh "$rt"
check_eq "別クライアント: どちらの後でも本人は refresh できる" "$code" 200

rt=$(login)
revoke "$rt"
check_eq "revoke: 200" "$code" 200
check_eq "revoke: 本文は空" "$body" ""
refresh "$rt"
check_eq "revoke: 失効した refresh_token は invalid_grant" "$code $error" "400 invalid_grant"

revoke "nope"
check_eq "revoke: 存在しない値も 200" "$code" 200
revoke ""
check_eq "revoke: token が空なら invalid_request" "$code $error" "400 invalid_request"
revoke "$rt" "tegata-sample:wrong"
check_eq "revoke: secret 違いは invalid_client" "$code $error" "401 invalid_client"

finish
