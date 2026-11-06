#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "$0")/lib.sh"

QUERY="client_id=tegata-sample&redirect_uri=${CALLBACK}&response_type=code&scope=openid%20profile%20email&state=smoke-state&nonce=smoke-nonce&code_challenge=${CHALLENGE}&code_challenge_method=S256"
PASSWORD="correct horse battery"
PREFIX="smoke-$(date +%s)-$RANDOM"
UUID='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

require_jq
require_server

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

id_of() {
  sed -n 's/.*name="id" value="\([^"]*\)".*/\1/p' "$1"
}

new_id() {
  curl -fsS -o "$tmp/login" "$BASE/authorize?$QUERY"
  id_of "$tmp/login"
}

read_page() {
  local shown form
  shown=$(sed -n 's/^ *\(Error occured\. .*[^ ]\) *$/\1/p; s/^ *\(Sign Up is success\.\) *$/\1/p' "$tmp/body")
  form=$(sed -n 's/.*<form action="\([^"]*\)".*/\1/p' "$tmp/body")
  page="$status | $shown | $form | $(id_of "$tmp/body")"
}

get_register() {
  status=$(curl -sS -o "$tmp/body" -w '%{http_code}' "$BASE/register?id=$1")
  read_page
}

register() {
  status=$(curl -sS -o "$tmp/body" -w '%{http_code}' \
    --data-urlencode "id=$1" --data-urlencode "username=$2" --data-urlencode "password=$3" \
    --data-urlencode "name=Smoke" --data-urlencode "email=${4:-}" "$BASE/register")
  read_page
}

login() {
  location=$(curl -sS -o /dev/null -w '%{http_code} %{redirect_url}' \
    --data-urlencode "id=$1" --data-urlencode "username=$2" --data-urlencode "password=$3" \
    -d action=approve "$BASE/authorize")
}

userinfo() {
  local code token
  code=$(sed -n 's/.*code=\([^&]*\).*/\1/p' <<<"$location")
  token=$(curl -fsS -u tegata-sample:dummy-secret \
    -d grant_type=authorization_code --data-urlencode "code=$code" \
    --data-urlencode "redirect_uri=$CALLBACK" --data-urlencode "code_verifier=$VERIFIER" \
    "$BASE/token" | jq -r .access_token)
  curl -fsS -H "Authorization: Bearer $token" "$BASE/userinfo"
}

id=$(new_id)
check "ログイン画面: 登録画面へのリンクに同じ id が付く" "$(cat "$tmp/login")" "href=\"/register\\?id=$id\""

get_register "$id"
check_eq "GET: 登録画面に同じ id が載る" "$page" "200 |  | /register | $id"
get_register bogus
check_eq "GET: 存在しない id は 400" "$status" 400

alice="$PREFIX-alice"
register "$id" "$alice" "$PASSWORD" alice@example.com
check_eq "登録: ログイン画面に同じ id で戻る" "$page" "200 | Sign Up is success. | /authorize | $id"

login "$id" "$alice" "$PASSWORD"
check "登録: 戻った id のまま新しいユーザーでログインできる" "$location" "^302 $CALLBACK\\?code=[A-Za-z0-9_-]{43}&state=smoke-state\$"
info=$(userinfo)
check "userinfo: sub は UUID" "$(jq -r .sub <<<"$info")" "$UUID"
check_eq "userinfo: preferred_username は登録した username" "$(jq -r .preferred_username <<<"$info")" "$alice"
check_eq "userinfo: email と email_verified=false" "$(jq -c '[.email, .email_verified]' <<<"$info")" '["alice@example.com",false]'

id=$(new_id)
jp="$PREFIX-jp"
register "$id" "$jp" "パスワードパスワードパスワード"
check_eq "日本語 15 文字・email なし: 登録できる" "$page" "200 | Sign Up is success. | /authorize | $id"
login "$id" "$jp" "パスワードパスワードパスワード"
check "日本語 15 文字・email なし: ログインできる" "$location" "^302 $CALLBACK\\?code="
check_eq "email なし: userinfo は email も email_verified も返さない" \
  "$(userinfo | jq -c '[has("email"), has("email_verified")]')" '[false,false]'

id=$(new_id)
register "$id" "$alice" "another password!"
check_eq "重複: 登録済みの username は再表示" "$page" "200 | Error occured. Username is already in use. | /register | $id"
register "$id" username "another password!"
check_eq "重複: シードの username も再表示" "$page" "200 | Error occured. Username is already in use. | /register | $id"
register "$id" "" "$PASSWORD"
check_eq "username が空は再表示" "$page" "200 | Error occured. username is required | /register | $id"
register "$id" "$PREFIX-short" "12345678901234"
check_eq "パスワード 14 文字は再表示" "$page" "200 | Error occured. Please make your password 15-64 characters long | /register | $id"
register "$id" "$PREFIX-jp14" "パスワードパスワードパスワー"
check_eq "日本語 14 文字（42 バイト）は再表示" "$page" "200 | Error occured. Please make your password 15-64 characters long | /register | $id"
login "$id" "$PREFIX-short" "12345678901234"
check_eq "はじかれた username は登録されていない" "$location" "200 "

register bogus "$PREFIX-bogus" "$PASSWORD"
check_eq "存在しない id は 400" "$status" 400

finish
