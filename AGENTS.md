# AGENTS.md — AI Agent Guide for cmdline-openid-client

## Project Overview
A Go CLI tool that performs OAuth2/OIDC flows (authorization code, client credentials, password, token exchange, etc.) against OIDC-compliant servers, primarily SAP Cloud Identity Services (IAS) and Cloud Foundry UAA.

## Architecture

```
openid-client/openid-client.go   # main package — CLI entry point, flag parsing, flow dispatch
pkg/client/
  client.go    # authorization_code, refresh, client_credentials, password flows + private_key_jwt helpers
  exchange.go  # token-exchange, jwt-bearer, saml-bearer, passcode, introspect, revoke, userinfo, token-list
  token.go     # shared OpenIdToken struct {IdToken, AccessToken, RefreshToken}
pkg/cf/
  config.go            # read/write CF ~/.cf/config.json for UAA simulation (-cf flag)
  home_dir_unix.go     # OS-specific home dir helpers
  home_dir_windows.go
```

## Build & Run

```bash
make                          # builds to ~/go/bin/openid-client
go build -o ~/go/bin/openid-client openid-client/openid-client.go
go test ./...                 # run all tests
go run github.com/strehle/cmdline-openid-client/openid-client@latest   # run without cloning
```

## Key Patterns

### Command dispatch
`main()` inspects `os.Args[1]` — if it doesn't start with `-`, it is treated as a command string; remaining args are parsed by `flag`. The default command (empty string) is `authorization_code`.

### Request building
All grant flows receive a `url.Values` (`requestMap`) pre-populated with `client_id`, `client_secret`, `client_assertion`, `token_format`, etc. Each `Handle*` function in `pkg/client` appends its `grant_type` and posts to the token endpoint.

### Client authentication precedence (in `main`)
1. `-client_assertion` (external JWT) → sets `privateKeyJwt`
2. `-client_jwt` P12 + `-pin` → `CreatePrivateKeyJwt` (x5t thumbprint as kid)
3. `-client_tls` P12 + `-pin` → mutual TLS `http.Client`
4. `-client_jwt_key` PEM + `-client_jwt_kid` → `CreatePrivateKeyJwtKid`
5. `-client_secret` → plain secret in form body

### OIDC provider / endpoint resolution
`oidc.NewProvider` fetches the `.well-known/openid-configuration`. If that fails and `-url` is set, endpoints are set directly from `-url`. The `provider.Claims(&claims)` struct captures `authorization_endpoint`, `token_endpoint`, `introspection_endpoint`, `userinfo_endpoint`, and `end_session_endpoint`.

### Environment variables (override CLI flags when flag value is empty)
| Var | Flag |
|---|---|
| `OPENID_ISSUER` | `-issuer` |
| `OPENID_ID` | `-client_id` |
| `OPENID_SECRET` | `-client_secret` |
| `OPENID_PIN` | `-pin` |
| `OPENID_USER` | `-username` |
| `OPENID_PASSWORD` | `-password` |
| `OPENID_FORMAT` | `-token_format` |
| `OPENID_QUERY` | `-request_query` |

### IAS-specific conventions
- `provider_name` is transformed to `resource=urn:sap:identity:application:provider:name:<name>` in the token request.
- `-sso` adds `resource=urn:sap:identity:sso` + `requested_token_type=urn:ietf:params:oauth:token-type:access_token`.
- `HandleCorpIdpExchangeFlow` rewrites `/oauth2/token` → `/oauth2/exchange/corporateidp`.
- The `sso` command rewrites `/oauth2/authorize` → `/saml2/idp/sso`.
- `HandleTokenRevocation` rewrites `/oauth2/token` → `/oauth2/revoke`.

### `-export` flag
`showResponse(export, token)` prints only the named token field (`id_token`, `access_token`, or `refresh_token`) — used to pipe a single token value to scripts.

### CF simulation (`-cf`)
Reads `~/.cf/config.json` via `pkg/cf` to populate issuer/client credentials; writes tokens back after successful calls (`cf.WriteUaaConfig`).

## Key Files to Read First
- `openid-client/openid-client.go` — entire CLI logic in one `main()` (798 lines)
- `pkg/client/exchange.go` — user-agent constant `agent = "OpenId Client/GO/1"` shared across all HTTP calls
- `pkg/client/token.go` — the single shared `OpenIdToken` struct

