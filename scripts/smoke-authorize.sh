#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

CALLBACK="http://localhost:9999/callback"
STATE="smoke-state"
QUERY="client_id=tegata-sample&redirect_uri=${CALLBACK}&response_type=code&scope=openid&state=${STATE}&nonce=smoke-nonce&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256"
LOGIN="username=username&password=password"

login_page() {
  curl -fsS "$BASE/authorize?$QUERY"
}

new_id() {
  login_page | sed -n 's/.*name="id" value="\([^"]*\)".*/\1/p'
}

post() {
  curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' -d "$1" "$BASE/login"
}

require_server

page=$(login_page)
check "GET: hidden は 1 個だけ" "$(grep -c 'type="hidden"' <<<"$page")" '^1$'
check "GET: hidden は id" "$(grep 'type="hidden"' <<<"$page")" 'name="id" value="[A-Za-z0-9_-]{43}"'
check "GET: state はページに出ない" "$(grep -c "$STATE" <<<"$page" || true)" '^0$'

page=$(curl -fsS -d "$QUERY" "$BASE/authorize")
check "POST: 本文の認可リクエストでもログイン画面を返す" "$(grep 'type="hidden"' <<<"$page")" 'name="id" value="[A-Za-z0-9_-]{43}"'
id=$(sed -n 's/.*name="id" value="\([^"]*\)".*/\1/p' <<<"$page")
check "POST: そのままログインすると code と state を返す" \
  "$(post "id=$id&$LOGIN&action=approve")" "^302 $CALLBACK\\?code=[A-Za-z0-9_-]{43}&state=$STATE\$"

id=$(new_id)
retry=$(curl -sS -d "id=$id&username=username&password=wrong&action=approve" "$BASE/login")
check "パスワード違い: エラーを表示する" "$retry" 'invalid username or password'
check "パスワード違い: 同じ id で再表示する" "$retry" "name=\"id\" value=\"$id\""

check "approve: code と state を付けてリダイレクト" \
  "$(post "id=$id&$LOGIN&action=approve")" "^302 $CALLBACK\\?code=[A-Za-z0-9_-]{43}&state=$STATE\$"
check "approve の再送信は 400" "$(post "id=$id&$LOGIN&action=approve")" '^400 $'

check "存在しない id は 400" "$(post "id=bogus&$LOGIN&action=approve")" '^400 $'
check "id なしは 400" "$(post "$LOGIN&action=approve")" '^400 $'

id=$(new_id)
check "不正な action は 400" "$(post "id=$id&$LOGIN&action=foo")" '^400 $'
check "不正な action の後も id は残り deny できる" \
  "$(post "id=$id&$LOGIN&action=deny")" "^302 $CALLBACK\\?error=access_denied&.*state=$STATE\$"

id=$(new_id)
check "フォームの redirect_uri は無視する" \
  "$(post "id=$id&redirect_uri=http://evil/cb&$LOGIN&action=approve")" "^302 $CALLBACK\\?code="

finish
