# tegata
[![CI](https://github.com/HagaSpa/tegata/actions/workflows/ci.yaml/badge.svg)](https://github.com/HagaSpa/tegata/actions/workflows/ci.yaml)

tegata is an OpenID Provider (OAuth 2.0 Authorization Server) written in Go with only the standard library. Reinventing the wheel for learning purposes: the protocol is assembled and verified by hand (JWT, JWK, PKCE, request validation), and only the cryptographic primitives come from the standard library.

It passes the OpenID Foundation conformance suite for the Basic OP, Config OP and RP-Initiated Logout OP profiles with no failures. See [Conformance testing](#conformance-testing).

The name comes from the travel permit of the Edo period (関所手形): an office issues it, and a checkpoint inspects it before letting the holder through.

- https://openid-foundation-japan.github.io/rfc6749.ja.html
- https://tex2e.github.io/rfc-translater/html/rfc9700.html#Best-Current-Practice-for-OAuth-2-0-Security

| compose service | OAuth 2.0 role | directory | role |
|---|---|---|---|
| `openid-provider` | Authorization Server | `cmd/op`, `internal/op` | tegata itself. Issues authorization codes, ID tokens and access tokens |
| `resource-server` | Resource Server | `cmd/rs`, `internal/rs` | Sample resource server. Serves `/notes` for access tokens issued by `openid-provider` |
| `relying-party` | Client | `example/rp` | Sample client with browser pages. Signs in, calls `resource-server` and logs out through `openid-provider` |

The main module uses only the Go standard library. `example/rp` is a separate module because it depends on go-oidc for verification.

## Running

It needs Docker with compose and [mise](https://mise.jdx.dev/).

```sh
mise dev:start    # build and start the three services, then open http://127.0.0.1:5556/
mise dev:stop     # stop and remove them
```

Sign in at the login page of tegata as `username` / `password`, or create a user from the sign-up page. The sample client then shows the ID token claims, the UserInfo response and the notes from the resource server, and has buttons for refreshing, revoking and every logout variant.

| port | service |
|---|---|
| 8080 | `openid-provider` |
| 9000 | `resource-server` |
| 5556 | `relying-party` |

```sh
mise test:lint    # gofmt and go vet
mise test:unit    # go test ./...
mise test:race    # go test -race ./...
mise test:smoke   # start the services and check the endpoints with curl
```

## What is implemented

| feature | spec |
|---|---|
| Authorization code flow (`response_type=code`) | [RFC 6749 §4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1), [Core §3.1](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth) |
| PKCE with `S256`. Optional for confidential clients, verified whenever a `code_challenge` is sent | [RFC 7636 §4](https://www.rfc-editor.org/rfc/rfc7636#section-4) |
| Client authentication with `client_secret_basic` and `client_secret_post` | [RFC 6749 §2.3.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.3.1) |
| ID tokens and access tokens as JWTs signed with RS256. JWT, JWS and JWK are built and verified without a library | [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515), [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) |
| Refresh tokens with `offline_access`, rotated on every use, and revocation | [RFC 6749 §6](https://www.rfc-editor.org/rfc/rfc6749#section-6), [Core §11](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess), [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) |
| OP session with `prompt=none`, `max_age` and `auth_time`. Without `prompt=none`, the login page is always shown | [Core §3.1.2.1](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest) |
| UserInfo with the `profile` and `email` scopes | [Core §5.3](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo), [Core §5.4](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims) |
| Discovery and JWKS | [Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html) |
| RP-Initiated Logout | [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html) |
| A separate resource server that verifies access tokens with the JWKS of the OP and checks `scope` | [RFC 6750](https://www.rfc-editor.org/rfc/rfc6750) |
| User registration with passwords hashed by PBKDF2-HMAC-SHA256 | tegata only |

## What is not implemented

tegata is not meant to be run as a service. Everything below is out of scope on purpose.

- Persistence. Clients are fixed in the source code. Users, sessions, authorization codes and refresh tokens live in memory, and the signing key is created at startup, so a restart invalidates every token
- Running more than one replica
- Key rotation
- Dynamic client registration ([RFC 7591](https://www.rfc-editor.org/rfc/rfc7591)) and public clients
- The implicit and hybrid flows, and every grant type other than `authorization_code` and `refresh_token`
- Request objects (`request`, `request_uri`), the `claims` parameter, `acr` and the `address` and `phone` scopes
- Revoking access tokens. They are self-contained JWTs that stay valid until they expire after one hour
- A separate consent page. The login page has the approve and deny buttons
- Limiting login attempts. The login form can be tried any number of times ([RFC 6749 §10.10](https://www.rfc-editor.org/rfc/rfc6749#section-10.10))
- TLS outside the conformance setup. `mise dev:start` serves http, and the development clients use http redirect URIs
- Audit logs

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
| `openid-provider` | `GET /static/` | tegata only | Serves the stylesheet of the login, sign-up and logout pages |
| `openid-provider` | `GET /` | tegata only | Returns `Hello, World!` |
| `resource-server` | `GET`, `POST /notes` | OAuth 2.0 (a protected resource. The access token is sent as in [RFC 6750 §2.1](https://www.rfc-editor.org/rfc/rfc6750#section-2.1)) | Reads notes with `notes.read` and writes notes with `notes.write` |
| `relying-party` | `GET /` | OpenID Connect (the `post_logout_redirect_uri` target, [RP-Initiated Logout 1.0 §3](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout)) | The top page. Has the sign-in buttons, and checks the `state` when `openid-provider` redirects back after logout |
| `relying-party` | `GET /login` | tegata only (demo) | Creates `state`, `nonce` and the PKCE verifier, then redirects to `/authorize`. `?prompt=none` adds `prompt=none` |
| `relying-party` | `GET /callback` | OAuth 2.0 (the redirection endpoint, [RFC 6749 §3.1.2](https://www.rfc-editor.org/rfc/rfc6749#section-3.1.2)) | Receives the code, exchanges it for tokens, verifies the ID token, calls `/userinfo` and `/notes`, then redirects to `/home` |
| `relying-party` | `GET /home`, `GET /notes`, `POST /expire`, `POST /revoke` | tegata only (demo) | Shows the ID token claims, UserInfo and notes, calls the resource server again, marks the access token as expired, and revokes the refresh token |
| `relying-party` | `POST /logout` | tegata only (demo) | Forgets the session at the RP and sends the browser to `end_session_endpoint`, with or without `id_token_hint` and `post_logout_redirect_uri`, or with an unregistered `post_logout_redirect_uri` |
| `relying-party` | `GET /static/` | tegata only (demo) | Serves the stylesheet of the sample client pages |

## Conformance testing

### Results

Results of `mise conformance:test` on 2026-11-17. No module failed.

| plan | modules | PASSED | REVIEW | WARNING | SKIPPED | FAILED |
|---|---|---|---|---|---|---|
| Basic OP (`oidcc-basic-certification-test-plan`) | 35 | 22 | 4 | 5 | 4 | 0 |
| Config OP (`oidcc-config-certification-test-plan`) | 1 | 1 | 0 | 0 | 0 | 0 |
| RP-Initiated Logout OP (`oidcc-rp-initiated-logout-certification-test-plan`) | 11 | 3 | 8 | 0 | 0 | 0 |

- `REVIEW` means the suite took a screenshot that a human has to check, such as tegata's error page for an unregistered `redirect_uri`. It is not a failure.
- `SKIPPED` covers features that tegata does not advertise: the `address` and `phone` scopes and request objects.
- `WARNING` means the module passed but tegata did not do something the specs only recommend or leave optional.

| module with a warning | what tegata does |
|---|---|
| `oidcc-userinfo-post-body` | Does not accept the access token in the POST body of `/userinfo`. Only the `Authorization` header is supported |
| `oidcc-scope-profile` | Returns `name` and `preferred_username` for the `profile` scope, not every claim of that scope |
| `oidcc-ensure-request-with-acr-values-succeeds` | Does not return an `acr` claim |
| `oidcc-codereuse-30seconds` | Rejects the reused authorization code, but the access token issued from its first use stays valid |
| `oidcc-claims-essential` | Ignores the `claims` parameter |

These are self-run results, not an OpenID certification.

### Who runs the tests

The [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) runs the tests.
It runs locally in containers, acts as the relying party, sends requests to tegata and checks every response against the specs.
The test logic lives in the suite, not in this repository.

### How to run the tests

Tests are run with `mise conformance:test`. It first builds and starts tegata and the suite with `compose.conformance.yaml` and waits until the suite is ready. Then it creates a test plan in the suite and starts every test module in order through the suite's API. When a module needs a login, the suite's own headless browser opens tegata's login page and signs in as `username` / `password`, following `scripts/conformance-config.json`. Each result is printed as soon as the module finishes.

```sh
mise conformance:test     # start tegata and the suite, run the Basic OP, Config OP and RP-Initiated Logout OP tests and print the results
```

```
== Basic OP (https://localhost.emobix.co.uk:8443/plan-detail.html?plan=Tx6Czkc9yCyDZ)
PASSED           oidcc-server
WARNING          oidcc-userinfo-post-body
                   UserInfoEndpointWithAccessTokenInBodyNotSupported: The server returned a non-2xx HTTP response, and hence does not appear to support access tokens passed in the POST body.
                   https://localhost.emobix.co.uk:8443/log-detail.html?log=...
REVIEW           oidcc-ensure-registered-redirect-uri
                   https://localhost.emobix.co.uk:8443/log-detail.html?log=...
...
== summary
  26 PASSED
  12 REVIEW
   4 SKIPPED
   5 WARNING
```

- `mise conformance:test basic <module>...` runs only the given Basic OP modules. `mise conformance:test config` runs only Config OP. `mise conformance:test logout <module>...` runs only the given RP-Initiated Logout OP modules.
- A module that did not pass is printed with its first failure and the URL of its log page. The log page lists every check with the spec section it comes from.
- After changing tegata, just run `mise conformance:test` again. It rebuilds the tegata image and recreates the container.
- tegata uses port 8080 like `mise dev:start` and `mise test:smoke`, so stop those first with `mise dev:stop`.
- `mise conformance:start` only starts tegata and the suite, for using the web UI. `mise conformance:stop` stops both. Plans and results stay in the `mongodb` volume.

### How it is wired

| item | value | why |
|---|---|---|
| issuer | `https://tegata.localhost:8080` | The suite runs in a container and calls Discovery, JWKS, `/authorize`, `/token` and `/userinfo`. A browser on the host also reaches `/authorize` when a module is run by hand from the web UI. Both must reach tegata through the same issuer. In `compose.conformance.yaml`, tegata has the network alias `tegata.localhost`, so the suite reaches it by that name. The host resolves `*.localhost` to 127.0.0.1 and reaches tegata through the published port 8080 |
| TLS | self-signed certificate in `.tls/` | The suite requires https for the discovery URL and every endpoint. `mise conformance:start` first runs the hidden task `conformance:cert`, which creates the certificate and key for `tegata.localhost` with Go's `generate_cert.go` when they do not exist yet. `.tls/` is not committed. tegata serves https when `TLS_CERT_FILE` and `TLS_KEY_FILE` are set. The suite does not verify the certificate, so no CA is needed. A browser on the host shows a warning for it. `mise dev:start` and `mise test:smoke` stay on http |
| clients | `conformance` / `conformance-secret-at-least-32-bytes`, `conformance2` / `conformance2-secret` | Registered in `internal/op/registry/client.go`. Some modules, such as `oidcc-refresh-token`, need a second client. `oidcc-rp-initiated-logout-bad-id-token-hint` signs a fake ID token with the client secret using HS256, which needs a key of at least 32 bytes ([RFC 7518 §3.2](https://www.rfc-editor.org/rfc/rfc7518#section-3.2)) |
| redirect URI | `https://localhost.emobix.co.uk:8443/test/a/tegata/callback` | The suite builds it from its base URL and the `alias` in the plan config |
| post logout redirect URI | `https://localhost.emobix.co.uk:8443/test/a/tegata/post_logout_redirect` | The suite builds it like the redirect URI, with `post_logout_redirect` in place of `callback`. Registered for `conformance` |
| login automation | `browser` and `override` in `scripts/conformance-config.json` | Tells the suite's headless browser how to fill in tegata's login form, how to confirm a logout, and which page to expect for modules that take a screenshot |
