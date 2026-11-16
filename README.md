# tegata
tegata is an OpenID Provider (OAuth 2.0 Authorization Server). Reinventing the wheel for learning purposes.
https://openid-foundation-japan.github.io/rfc6749.ja.html

| compose service | OAuth 2.0 role | directory | role |
|---|---|---|---|
| `openid-provider` | Authorization Server | `cmd/op`, `internal/op` | tegata itself. Issues authorization codes, ID tokens and access tokens |
| `resource-server` | Resource Server | `cmd/rs`, `internal/rs` | Sample resource server. Serves `/notes` for access tokens issued by `openid-provider` |
| `relying-party` | Client | `tools/rp` | Sample client with browser pages. Signs in, calls `resource-server` and logs out through `openid-provider` |

The main module uses only the Go standard library. `tools/rp` is a separate module because it depends on go-oidc for verification.

## Endpoints

OpenID Connect is built on top of OAuth 2.0. Some endpoints come from OAuth 2.0 as they are, some are OAuth 2.0 endpoints that OpenID Connect extends, and some exist only in OpenID Connect.

| service | endpoint | spec | what it does |
|---|---|---|---|
| `openid-provider` | `GET /.well-known/openid-configuration` | OpenID Connect ([Discovery 1.0 §4](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfig)) | Returns the provider metadata: the issuer, the endpoint URLs and the supported values |
| `openid-provider` | `GET /.well-known/jwks.json` | OpenID Connect (`jwks_uri` in [Discovery 1.0 §3](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)). The format is a JWK Set ([RFC 7517 §5](https://www.rfc-editor.org/rfc/rfc7517#section-5)) | Returns the public keys for verifying ID tokens and access tokens |
| `openid-provider` | `GET`, `POST /authorize` | OAuth 2.0 ([RFC 6749 §3.1](https://www.rfc-editor.org/rfc/rfc6749#section-3.1)), extended by OpenID Connect ([Core §3.1.2](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint): the `openid` scope, `nonce`, `prompt`, `max_age`) | Validates the authorization request and shows the login page. With `prompt=none`, issues a code from the existing OP session instead |
| `openid-provider` | `POST /login` | tegata only | Receives the login form, starts the OP session and redirects back to the client with a code |
| `openid-provider` | `GET`, `POST /register` | tegata only | Shows the sign-up form and registers a user |
| `openid-provider` | `POST /token` | OAuth 2.0 ([RFC 6749 §3.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.2)), extended by OpenID Connect ([Core §3.1.3](https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint): the ID token in the response) | Exchanges an authorization code or a refresh token for tokens |
| `openid-provider` | `POST /revoke` | OAuth 2.0 ([RFC 7009 §2](https://www.rfc-editor.org/rfc/rfc7009#section-2)) | Revokes a refresh token |
| `openid-provider` | `GET`, `POST /userinfo` | OpenID Connect ([Core §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo)) | Returns claims about the user for an access token. In OAuth 2.0 terms, it is a protected resource hosted by the OP |
| `openid-provider` | `GET`, `POST /logout` | OpenID Connect ([RP-Initiated Logout 1.0 §2](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout)) | Ends the OP session. With a valid `id_token_hint` and a registered `post_logout_redirect_uri`, redirects back to the client with `state`. Without `id_token_hint`, or when it does not match the OP session, shows a confirmation page instead |
| `openid-provider` | `POST /logout/confirm` | tegata only | Receives the confirmation page and ends the OP session |
| `openid-provider` | `GET /` | tegata only | Returns `Hello, World!` |
| `resource-server` | `GET`, `POST /notes` | OAuth 2.0 (a protected resource. The access token is sent as in [RFC 6750 §2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)) | Reads notes with `notes.read` and writes notes with `notes.write` |
| `relying-party` | `GET /` | OpenID Connect (the `post_logout_redirect_uri` target, [RP-Initiated Logout 1.0 §3](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout)) | The top page. Has the sign-in buttons, and checks the `state` when `openid-provider` redirects back after logout |
| `relying-party` | `GET /login` | tegata only (demo) | Creates `state`, `nonce` and the PKCE verifier, then redirects to `/authorize`. `?prompt=none` adds `prompt=none` |
| `relying-party` | `GET /callback` | OAuth 2.0 (the redirection endpoint, [RFC 6749 §3.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2)) | Receives the code, exchanges it for tokens, verifies the ID token, calls `/userinfo` and `/notes`, then redirects to `/home` |
| `relying-party` | `GET /home`, `GET /notes`, `POST /expire`, `POST /revoke` | tegata only (demo) | Shows the ID token claims, UserInfo and notes, calls the resource server again, marks the access token as expired, and revokes the refresh token |
| `relying-party` | `POST /logout` | tegata only (demo) | Forgets the session at the RP and sends the browser to `end_session_endpoint`, with or without `id_token_hint` and `post_logout_redirect_uri`, or with an unregistered `post_logout_redirect_uri` |

## Conformance testing

### Who runs the tests

The [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) runs the tests.
It runs locally in containers, acts as the relying party, sends requests to tegata and checks every response against the specs.
The test logic lives in the suite, not in this repository.

### How to run the tests

Tests are run with `mise conformance:test`. It first builds and starts tegata and the suite with `compose.conformance.yaml` and waits until the suite is ready. Then it creates a test plan in the suite and starts every test module in order through the suite's API. When a module needs a login, the suite's own headless browser opens tegata's login page and signs in as `username` / `password`, following `scripts/conformance-config.json`. Each result is printed as soon as the module finishes.

```sh
mise conformance:test     # start tegata and the suite, run the Basic OP and Config OP tests and print the results
```

```
== Basic OP (https://localhost.emobix.co.uk:8443/plan-detail.html?plan=X2qVJVnZFxUrg)
FAILED           oidcc-server
                   CheckIfAuthorizationEndpointError: The authorization was expected to succeed, but the server returned an error from the authorization endpoint (error=invalid_request, error_description=code_challenge is required)
                   https://localhost.emobix.co.uk:8443/log-detail.html?log=gVzst6mtcqvXgzb
PASSED           oidcc-ensure-request-with-valid-pkce-succeeds
REVIEW           oidcc-ensure-registered-redirect-uri
                   https://localhost.emobix.co.uk:8443/log-detail.html?log=aWmRIdxl5vF5U37
== summary
   1 FAILED
   1 PASSED
   1 REVIEW
```

- `mise conformance:test basic <module>...` runs only the given Basic OP modules. `mise conformance:test config` runs only Config OP.
- A module that did not pass is printed with its first failure and the URL of its log page. The log page lists every check with the spec section it comes from.
- `REVIEW` means the suite took a screenshot that a human has to check, such as tegata's error page for an unregistered `redirect_uri`. It is not a failure.
- After changing tegata, just run `mise conformance:test` again. It rebuilds the tegata image and recreates the container.
- tegata uses port 8080 like `mise dev:start` and `mise test:smoke`, so stop those first with `mise dev:stop`.
- `mise conformance:start` only starts tegata and the suite, for using the web UI. `mise conformance:stop` stops both. Plans and results stay in the `mongodb` volume.

### How it is wired

| item | value | why |
|---|---|---|
| issuer | `https://tegata.localhost:8080` | The suite runs in a container and calls Discovery, JWKS, `/authorize`, `/token` and `/userinfo`. A browser on the host also reaches `/authorize` when a module is run by hand from the web UI. Both must reach tegata through the same issuer. In `compose.conformance.yaml`, tegata has the network alias `tegata.localhost`, so the suite reaches it by that name. The host resolves `*.localhost` to 127.0.0.1 and reaches tegata through the published port 8080 |
| TLS | self-signed certificate in `.tls/` | The suite requires https for the discovery URL and every endpoint. `mise conformance:start` first runs the hidden task `conformance:cert`, which creates the certificate and key for `tegata.localhost` with Go's `generate_cert.go` when they do not exist yet. `.tls/` is not committed. tegata serves https when `TLS_CERT_FILE` and `TLS_KEY_FILE` are set. The suite does not verify the certificate, so no CA is needed. A browser on the host shows a warning for it. `mise dev:start` and `mise test:smoke` stay on http |
| clients | `conformance` / `conformance-secret`, `conformance2` / `conformance2-secret` | Registered in `internal/op/registry/client.go`. Some modules, such as `oidcc-refresh-token`, need a second client |
| redirect URI | `https://localhost.emobix.co.uk:8443/test/a/tegata/callback` | The suite builds it from its base URL and the `alias` in the plan config |
| login automation | `browser` and `override` in `scripts/conformance-config.json` | Tells the suite's headless browser how to fill in tegata's login form, and which page to expect for modules that take a screenshot |
