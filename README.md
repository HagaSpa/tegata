# tegata
tegata is an OpenID Provider (OAuth 2.0 Authorization Server). Reinventing the wheel for learning purposes.
https://openid-foundation-japan.github.io/rfc6749.ja.html

| compose service | directory | role |
|---|---|---|
| `openid-provider` | `cmd/op`, `internal/op` | tegata itself. Issues authorization codes, ID tokens and access tokens |
| `relying-party` | `tools/rp` | Sample client that signs in through `openid-provider` |

The main module uses only the Go standard library. `tools/rp` is a separate module because it depends on go-oidc for verification.
