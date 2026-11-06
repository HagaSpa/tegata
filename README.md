# tegata
tegata is an OpenID Provider (OAuth 2.0 Authorization Server). Reinventing the wheel for learning purposes.
https://openid-foundation-japan.github.io/rfc6749.ja.html

| compose service | directory | role |
|---|---|---|
| `openid-provider` | `cmd/op`, `internal/op` | tegata itself. Issues authorization codes, ID tokens and access tokens |
| `relying-party` | `tools/rp` | Sample client that signs in through `openid-provider` |

The main module uses only the Go standard library. `tools/rp` is a separate module because it depends on go-oidc for verification.

## Conformance testing

### Who runs the tests

The [OpenID Foundation conformance suite](https://gitlab.com/openid/conformance-suite) runs the tests.
It runs locally in containers, acts as the relying party, sends requests to tegata and checks every response against the specs.
The test logic lives in the suite, not in this repository.

### How to run the tests

Tests are run with `mise conformance-test`. It first builds and starts tegata and the suite with `compose.conformance.yaml` and waits until the suite is ready. Then it creates a test plan in the suite and starts every test module in order through the suite's API. When a module needs a login, the suite's own headless browser opens tegata's login page and signs in as `username` / `password`, following `scripts/conformance-config.json`. Each result is printed as soon as the module finishes.

```sh
mise conformance-test     # start tegata and the suite, run the Basic OP and Config OP tests and print the results
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

- `mise conformance-test basic <module>...` runs only the given Basic OP modules. `mise conformance-test config` runs only Config OP.
- A module that did not pass is printed with its first failure and the URL of its log page. The log page lists every check with the spec section it comes from.
- `REVIEW` means the suite took a screenshot that a human has to check, such as tegata's error page for an unregistered `redirect_uri`. It is not a failure.
- After changing tegata, just run `mise conformance-test` again. It rebuilds the tegata image and recreates the container.
- tegata uses port 8080 like `mise serve` and `mise start`, so stop those first.
- `mise conformance` only starts tegata and the suite, for using the web UI. `mise conformance-stop` stops both. Plans and results stay in the `mongodb` volume.

### How it is wired

| item | value | why |
|---|---|---|
| issuer | `http://tegata.localhost:8080` | The suite runs in a container and calls Discovery, JWKS, `/authorize`, `/token` and `/userinfo`. A browser on the host also reaches `/authorize` when a module is run by hand from the web UI. Both must reach tegata through the same issuer. In `compose.conformance.yaml`, tegata has the network alias `tegata.localhost`, so the suite reaches it by that name. The host resolves `*.localhost` to 127.0.0.1 and reaches tegata through the published port 8080 |
| clients | `conformance` / `conformance-secret`, `conformance2` / `conformance2-secret` | Registered in `internal/op/registry/client.go`. Some modules, such as `oidcc-refresh-token`, need a second client |
| redirect URI | `https://localhost.emobix.co.uk:8443/test/a/tegata/callback` | The suite builds it from its base URL and the `alias` in the plan config |
| login automation | `browser` and `override` in `scripts/conformance-config.json` | Tells the suite's headless browser how to fill in tegata's login form, and which page to expect for modules that take a screenshot |
