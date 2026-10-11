# tegata
tegata is an OpenID Provider (OAuth 2.0 Authorization Server). Reinventing the wheel for learning purposes.

| compose service | role |
|---|---|
| `openid-provider` | tegata itself. Issues authorization codes, ID tokens and access tokens |
| `relying-party` | Sample client (`tools/rp`) that signs in through `openid-provider` |
