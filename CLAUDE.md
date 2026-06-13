# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
make                    # build to ~/go/bin/openid-client
go build -o ~/go/bin/openid-client openid-client/openid-client.go
go test ./...           # run all tests
go test ./pkg/client/...  # run a single package's tests
```

## Architecture

Single-binary Go CLI. All flag parsing and command dispatch lives in `openid-client/openid-client.go` (`main()`). Shared logic lives in two packages:

- `pkg/client/` — all OAuth2/OIDC flow handlers
  - `client.go` — `authorization_code`, `refresh`, `client_credentials`, `password` flows; private_key_jwt helpers
  - `exchange.go` — `token-exchange`, `jwt-bearer`, `saml-bearer`, `passcode`, `introspect`, `revoke`, `userinfo`, `token-list`; defines the `agent` HTTP user-agent constant used everywhere
  - `token.go` — shared `OpenIdToken` struct `{IdToken, AccessToken, RefreshToken}`
- `pkg/cf/` — reads/writes `~/.cf/config.json` for CF UAA simulation (`-cf` flag)

**Command dispatch:** `main()` checks if `os.Args[1]` starts with `-`; if not, it's treated as a command name and remaining args are parsed by `flag`. Empty command defaults to `authorization_code`.

**Request building:** `main()` builds a shared `url.Values` (`requestMap`) with `client_id`, `client_secret`, `client_assertion`, and `token_format`, then passes it to the relevant handler. Exception: `authorization_code` and `refresh` flows build their own `url.Values` inside their handlers.

**Client auth precedence** (resolved in `main` before any handler is called):
1. `-client_assertion` → external JWT (`privateKeyJwt`)
2. `-client_jwt` P12 + `-pin` → `CreatePrivateKeyJwt` (x5t thumbprint as kid)
3. `-client_tls` P12 + `-pin` → mutual TLS `http.Client`
4. `-client_jwt_key` PEM + `-client_jwt_kid` → `CreatePrivateKeyJwtKid`
5. `-client_secret` → plain secret in form body (exception: `HandleCorpIdpExchangeFlow` uses HTTP Basic Auth instead)

**OIDC discovery:** `oidc.NewProvider` fetches `.well-known/openid-configuration`. If discovery fails and `-url` is set with a non-empty command, endpoints fall back to the `-url` value directly (does not apply to the default `authorization_code` flow).

**The `decode` command** is local-only (no network, no `-issuer`/`-client_id` needed). It splits the JWT on `.`, base64url-decodes header and payload, and pretty-prints them with jq-style ANSI colors (implemented in `pkg/client/exchange.go` with no external deps). Flags: `-header` (header only), `-payload` (payload only), `-raw` (plain JSON without colors or labels — requires `-header` or `-payload`). The command exits before OIDC discovery.

**IAS-specific URL rewrites** (done inside handlers):
- `HandleCorpIdpExchangeFlow`: `/oauth2/token` → `/oauth2/exchange/corporateidp`
- `sso` command: `/oauth2/authorize` → `/saml2/idp/sso`
- `HandleTokenRevocation`: `/oauth2/token` → `/oauth2/revoke`
- `HandlePasscode`: calls `GET {issuer}/service/users/passcode`

**Environment variables** fall back when the corresponding flag is empty: `OPENID_ISSUER`, `OPENID_ID`, `OPENID_SECRET`, `OPENID_PIN`, `OPENID_USER`, `OPENID_PASSWORD`, `OPENID_FORMAT`, `OPENID_QUERY`.

See `AGENTS.md` for deeper detail on token-exchange parameter mapping, SSO token flow, and passcode flow.
