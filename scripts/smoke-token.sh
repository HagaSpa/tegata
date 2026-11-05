#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

USERINFO_AUD="$BASE/userinfo"
RS_AUD="http://localhost:9000"

require_jq

segment() {
  jq -cR "split(\".\")[$1] | gsub(\"-\";\"+\") | gsub(\"_\";\"/\") | @base64d | fromjson"
}

claim() {
  segment 1 <<<"$1" | jq -c ".$2"
}

userinfo_status() {
  curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $1" "$BASE/userinfo"
}

require_server

check_eq "Discovery: scopes_supported に notes.* と offline_access がある" \
  "$(curl -fsS "$BASE/.well-known/openid-configuration" | jq -c .scopes_supported)" \
  '["openid","notes.read","notes.write","offline_access"]'

check_scope() {
  local scope=$1 want_aud=$2
  local res at it
  res=$(get_tokens "$scope")
  at=$(jq -r .access_token <<<"$res")
  it=$(jq -r .id_token <<<"$res")
  local label="scope=${scope//%20/ }"

  check_eq "$label: アクセストークンの aud" "$(claim "$at" aud)" "$want_aud"
  check_eq "$label: アクセストークンの typ は JWT" "$(segment 0 <<<"$at" | jq -c .typ)" '"JWT"'
  check_eq "$label: ID トークンの aud は client_id のまま" "$(claim "$it" aud)" '"tegata-sample"'
  check_eq "$label: userinfo はアクセストークンで 200" "$(userinfo_status "$at")" 200
  check_eq "$label: userinfo は ID トークンで 401" "$(userinfo_status "$it")" 401
}

check_scope "openid" "\"$USERINFO_AUD\""
check_scope "openid%20notes.read" "[\"$USERINFO_AUD\",\"$RS_AUD\"]"
check_scope "openid%20notes.read%20notes.write" "[\"$USERINFO_AUD\",\"$RS_AUD\"]"

finish
