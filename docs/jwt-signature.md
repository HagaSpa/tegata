# RS が OP のアクセストークンを検証できる理由

## 一言で

OP は **秘密鍵** で JWT に **署名** する。RS は OP が公開している **公開鍵** でその署名を **検証** する。検証に通れば「秘密鍵の持ち主（= OP）が作った」かつ「中身が書き換えられていない」と言える。RS はそのあとで初めて claims（`exp` / `iss` / `aud` / `scope`）を信用して中身を見る。

## ⚠️ 間違えやすい点: 暗号化・復号ではない

- JWT の payload は **暗号化されていない**。JSON を base64url にしただけなので、誰でも読めるし誰でも書き換えられる
- 公開鍵でやっているのは **復号ではなく署名の検証**。「この署名は、この header.payload に対して、対になる秘密鍵で作られたものか」を確かめる計算（RFC 8017 §8.2.2）
- 中身を読めないようにする JWT は別物（JWE、RFC 7516）。tegata のトークンは署名だけの JWS（RFC 7515）
- だから **秘密の情報を claims に入れてはいけない**

実際に試した結果（`sub` だけ書き換えて、署名はそのまま）:

```
payload（誰でも読める）: {"iss":"http://localhost:8080","sub":"u-0001","aud":null,"iat":0,"exp":1793682520}
元のトークン:                       err=<nil>
sub を u-0002 に書き換えたトークン: err=failed to verify signature: crypto/rsa: verification error
```

## 用語

| 用語 | 意味 |
|---|---|
| 秘密鍵 | OP だけが持つ。署名を作るのに使う。外に出さない |
| 公開鍵 | 秘密鍵と対になる鍵。誰に配ってもよい。署名の検証に使う |
| 署名 | header.payload から秘密鍵で計算した値（JWT の 3 つ目の部分）。秘密鍵がないと作れず、中身が 1 文字でも変わると合わなくなる |
| kid | どの鍵で署名したかを示す名前。JWT の header に入る。tegata では公開鍵のハッシュ |
| JWKS | OP が公開鍵を並べて公開している JSON（`/.well-known/jwks.json`） |

## 流れとコードの場所

```
[OP 起動時]   RSA の秘密鍵・公開鍵を作る。kid = 公開鍵のハッシュ    internal/op/keys/manager.go（NewManager）
[OP 発行時]   header.payload の SHA-256 を秘密鍵で署名               internal/jwt/jwt.go:56-57（jwt.Sign）
              → header.payload.署名 をつなげて JWT にする
[OP 公開]     公開鍵（n, e）と kid を JWKS に載せる

[RS 起動時]   Discovery で jwks_uri を知る（鍵はまだ取らない）      cmd/rs/main.go → keyset.GetJWKSURI
[RS 初回]     JWKS を取り、kid ごとに公開鍵を覚える                 internal/rs/keyset/keys.go（Key）
[RS 毎回]     header の kid で公開鍵を選び、署名を検証               internal/jwt/jwt.go:95-102（rsa.VerifyPKCS1v15）
              → 通ったら exp を確認                                  internal/jwt/jwt.go:112
              → iss → aud → scope を確認                             internal/rs/handler/middleware.go:56, 60, 64
```

公開鍵を取り直すのは「キャッシュにない kid が来たとき」だけ（前回の取得から 30 秒以内なら取り直さない）。OP を再起動すると鍵が作り直されて kid が変わるので、この取り直しが起きる。`mise demo-op-restart` で観察できる。

## 2 段階のチェック

| 段階 | 確かめること | 分かること |
|---|---|---|
| 署名 | 公開鍵で検証 | OP が作った・改ざんされていない |
| claims | `exp` | まだ期限内 |
| | `iss` | 信頼している OP が発行した |
| | `aud` | この RS 宛て（ID トークンや `/userinfo` 用ではない） |
| | `scope` | この操作が許されている |

署名を確かめる前の claims は、誰が書いたか分からないただの JSON。**順番は必ず「署名 → claims」**。

## ここから分かること

- **RS は id/pass を知らないし、ユーザーを自分で認証していない。** 「OP がユーザーを確かめ、その OP が署名した」ことを確かめているだけ
- **RS はリクエストごとに OP に問い合わせない。** 必要なのは公開鍵だけ（OP が止まっていても、キャッシュ済みの鍵で検証できる）
- **その裏返しで、アクセストークンは期限まで取り消せない。** OP 再起動直後も、古いトークンは RS で `200` のままだった（`mise demo-op-restart` の手順 2）
- だからアクセストークンは短命にして、長く使う役目は OP だけが見る **リフレッシュトークン** に分ける（OP は自分の保管所を見るので取り消せる）

## 出典

- RFC 7515（JWS）§5.2 — 署名付き JWT の検証手順
- RFC 7518 §3.3 — RS256 = RSASSA-PKCS1-v1_5 + SHA-256
- RFC 8017 §8.2.2 — RSASSA-PKCS1-v1_5 の検証操作
- RFC 7516（JWE）— 暗号化された JWT（tegata では使っていない）
- RFC 7517（JWK）— JWKS の形式
