# AGENTS.md — AI Agent Guide for cmdline-openid-client

## Project Overview
A Go CLI tool that performs OAuth2/OIDC flows (authorization code, client credentials, password, token exchange, etc.) against OIDC-compliant servers, primarily SAP Cloud Identity Services (IAS) and Cloud Foundry UAA.

## Architecture

```
openid-client/openid-client.go   # main package — CLI entry point, flag parsing, flow dispatch
pkg/client/
  client.go    # authorization_code, refresh, client_credentials, password flows + private_key_jwt helpers
  exchange.go  # token-exchange, jwt-bearer, saml-bearer, passcode, introspect, revoke, userinfo, token-list, register (dynamic client registration)
  token.go     # shared OpenIdToken struct {IdToken, AccessToken, RefreshToken}
pkg/cf/
  config.go            # read/write CF ~/.cf/config.json for UAA simulation (-cf flag)
  home_dir_unix.go     # OS-specific home dir helpers
  home_dir_windows.go
docs/
  client-auth-doc.md   # mTLS vs private_key_jwt explained, pro/cons, openssl setup steps
  token-exchange-doc.md # RFC7523 jwt-bearer, RFC8693 token-exchange params mapping
  passcode.md          # IAS-specific passcode service, dual-cert scripts
  sso_token.md         # SSO token flow, -sso flag, saml2/idp/sso endpoint
  register.md          # RFC7591 dynamic client registration, endpoint resolution, auth, flags
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
Request assembly is command-specific. Several non-authorization-code and non-refresh commands start from a `url.Values` (`requestMap`) prepared in `main` with shared parameters such as `client_id`, `client_secret`, `client_assertion`, and `token_format`, then pass it into the relevant handler in `pkg/client`. The authorization-code flow is an exception and builds its own params in `pkg/client/client.go`, and the refresh flow likewise constructs its own `url.Values` inside `HandleRefreshFlow` instead of reusing `requestMap`. Likewise, `grant_type` is not added uniformly in one place — depending on the command, it may be set in `main`, in the handler, or as part of a flow-specific parameter builder before the request is posted to the token endpoint.

### Client authentication precedence (in `main`)
1. `-client_assertion` (external JWT) → sets `privateKeyJwt` (RFC 7523 / OAuth2 flavour — token from another provider)
2. `-client_jwt` P12 + `-pin` → `CreatePrivateKeyJwt` (x5t thumbprint as kid; OIDC `private_key_jwt` flavour)
3. `-client_tls` P12 + `-pin` → mutual TLS `http.Client` (RFC 8705)
4. `-client_jwt_key` PEM + `-client_jwt_kid` → `CreatePrivateKeyJwtKid` (PEM key, explicit kid/x5t)
5. `-client_secret` → plain secret in form body

Use `openssl pkcs12 -export -legacy -inkey key.pem -in cert.pem -out final_result.p12 -passout pass:Test1234` to generate P12 files.

### TLS client configuration
Both the default `tlsClient` and the mTLS client are built with the same `tls.Config`. The `-tls_renegotiation` flag controls `tls.RenegotiationSupport` via the `tlsRenegotiationMode()` helper:

| Flag value              | `tls` constant |
|-------------------------|---|
| `` (empty) / `once` / 1 | `RenegotiateOnceAsClient` (default) |
| `never`    / 0          | `RenegotiateNever` |
| `freely`   / 2          | `RenegotiateFreelyAsClient` |

`-k` sets `InsecureSkipVerify: true` on both standard and mTLS clients uniformly.

### OIDC provider / endpoint resolution
`oidc.NewProvider` fetches the `.well-known/openid-configuration`. If discovery fails, direct endpoint fallback from `-url` is only used when `-url` is set and a non-empty command is being executed; it does not apply to the default authorization-code flow, which still relies on `oidc.NewProvider`. The `provider.Claims(&claims)` struct captures `authorization_endpoint`, `token_endpoint`, `introspection_endpoint`, `userinfo_endpoint`, and `end_session_endpoint`.

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
- `-sso` normally adds `resource=urn:sap:identity:sso` + `requested_token_type=urn:ietf:params:oauth:token-type:access_token`.
- For `jwt-bearer`, `-sso` is a two-step flow: first run the JWT bearer grant without those SSO token-exchange parameters, while forcing `refresh_expiry=0` and `token_format=opaque`; then perform a second token-exchange request to obtain the SSO token.
- `HandleCorpIdpExchangeFlow` rewrites `/oauth2/token` → `/oauth2/exchange/corporateidp`.
- The `sso` command rewrites `/oauth2/authorize` → `/saml2/idp/sso`.
- `HandleTokenRevocation` rewrites `/oauth2/token` → `/oauth2/revoke`.
- `HandlePasscode` calls `GET {issuer}/service/users/passcode` (IAS-only); requires `-user_tls` P12 for user mTLS.

### Token Exchange parameter mapping (see `docs/token-exchange-doc.md`)
CLI flags map to RFC 8693 parameters as follows:
- `-assertion` / `-token` → `subject_token`
- `-subject_type` → `subject_token_type` (provide only the last segment: `id_token`, `access_token`, `refresh_token`, `jwt`, `saml2-session`)
- `-requested_type` → `requested_token_type` (last segment: `id_token`, `access_token`, `saml2`, `saml2-header`)
- `-provider_name` → `resource=urn:sap:identity:application:provider:name:<name>`
- SAP-specific types `saml2-session` / `saml2-header` use `urn:sap:identity:oauth:token-type:` prefix instead of IETF.

### decode command
Decodes a signed JWT (JWS compact serialization) locally (no network call) and pretty-prints header and payload. It does not verify the signature or validate claims.

```bash
openid-client decode -token <jwt>            # both header and payload, colorized
openid-client decode -token <jwt> -header    # header only, colorized
openid-client decode -token <jwt> -payload   # payload only, colorized
openid-client decode -token <jwt> -header -raw   # header only, plain JSON (no colors/labels)
openid-client decode -token <jwt> -payload -raw  # payload only, plain JSON (no colors/labels)
```

Flags specific to `decode`:
- `-header` — show only the JWT header
- `-payload` — show only the JWT payload
- `-raw` — suppress colors and section labels; requires `-header` or `-payload`

`decode` does not require `-issuer` or `-client_id` and exits before OIDC discovery. The implementation lives in `HandleDecodeJwt` in `pkg/client/exchange.go`, which also contains `decodeJwtPart` (base64url decode + JSON unmarshal), `printColorJSON` / `colorizeLine` / `colorizeValue` (jq-style ANSI coloring — no external dependencies), and `printJwt` (raw vs colored dispatch).

### register command (see `docs/register.md`)
Performs OAuth 2.0 Dynamic Client Registration (RFC 7591). Builds a JSON client-metadata map in `main`, POSTs it to the registration endpoint, and prints the response via `HandleClientRegistration` in `pkg/client/exchange.go`.

- Endpoint resolution order: `-url` (used directly) → discovery `registration_endpoint` → fallback rewrite of `token_endpoint` `/oauth2/token` → `/oauth2/register` (IAS convention). Fails if none resolves.
- Auth: `-bearer` (initial access token → `Authorization: Bearer`) takes precedence; otherwise `-client_id` + `-client_secret` → HTTP Basic. Unauthenticated request if neither is set.
- `register` shares the `passcode`/`introspect`/`revoke`/`userinfo`/`token-list` group where `-client_id` defaults to `T000000` when omitted.
- Flag → metadata mapping (defaults applied in `main`):
  - `-redirect_uris` → `redirect_uris` (space-separated; default `http://localhost:<port>/callback`)
  - `-client_name` → `client_name` (default `openid-client`)
  - `-grant_types` → `grant_types` (space-separated; default `authorization_code client_credentials refresh_token password urn:ietf:params:oauth:grant-type:jwt-bearer`)
  - `-response_types` → `response_types` (space-separated; omitted if empty)
  - `-token_endpoint_auth_method` → `token_endpoint_auth_method` (default `client_secret_basic`)
  - `-jwks_uri` → `jwks_uri`; when set, forces `token_endpoint_auth_method=private_key_jwt`
- Non-201/200 responses cause `log.Fatal`.

### SSO Token Flow (see `docs/sso_token.md`)
Two-step IAS-specific flow:
1. Obtain opaque SSO token via token-exchange with `-sso` flag (or explicit `-resource urn:sap:identity:sso`)
2. Use `sso` command to open `{issuer}/saml2/idp/sso?sso_token=...&redirect_uri=...` in the OS browser

```bash
# Get SSO token, then open browser session
SSO_TOKEN=$(openid-client token-exchange -issuer <IAS> -client_id <ID> -client_secret <S> \
  -token "$AT" -subject_type access_token -requested_type access_token -sso -export access_token)
openid-client sso -issuer <IAS> -sso_token "$SSO_TOKEN" -redirect_uri "https://myapp.example.com"
```

### Passcode Flow (see `docs/passcode.md`)
IAS-only. Authenticates user via mTLS cert, returns a short-lived passcode usable as `-password`:
```bash
PASSCODE=$(openid-client passcode -issuer <IAS> -user_tls ./user.p12 -pin <PIN>)
openid-client password -issuer <IAS> -client_id <ID> -client_tls ./client.p12 -pin <PIN> \
  -username <user> -password "$PASSCODE" -export access_token
```
Note: `-client_id` defaults to `T000000` when omitted in `passcode` command.

### `-export` flag
`showResponse(export, token)` prints only the named token field (`id_token`, `access_token`, or `refresh_token`) — used to pipe a single token value to scripts.

### CF simulation (`-cf`)
Reads `~/.cf/config.json` via `pkg/cf` to populate issuer/client credentials; writes tokens back after successful calls (`cf.WriteUaaConfig`). `-origin` creates a UAA-specific `login_hint` JSON parameter.

## Key Files to Read First
- `openid-client/openid-client.go` — entire CLI logic in one `main()` (798 lines)
- `pkg/client/exchange.go` — user-agent constant `agent = "OpenId Client/GO/1"` shared across all HTTP calls
- `pkg/client/token.go` — the single shared `OpenIdToken` struct
- `docs/client-auth-doc.md` — when to use mTLS vs private_key_jwt and P12 generation steps
- `docs/token-exchange-doc.md` — parameter mapping and SCI-specific token type URNs
