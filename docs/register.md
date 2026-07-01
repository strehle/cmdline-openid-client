# Dynamic Client Registration (RFC 7591)

The `register` command performs [OAuth 2.0 Dynamic Client Registration (RFC 7591)](https://www.rfc-editor.org/rfc/rfc7591).
It sends a JSON client metadata document to the provider's registration endpoint and prints the
registration response (which typically contains the newly issued `client_id` and, for confidential
clients, a `client_secret`).

## Endpoint resolution

The registration endpoint is resolved in this order:

1. `-url` — if set, it is used directly as the registration endpoint.
2. `registration_endpoint` from the OIDC discovery document (`.well-known/openid-configuration`).
3. Fallback: the `token_endpoint` with `/oauth2/token` rewritten to `/oauth2/register` (IAS convention).

If no endpoint can be determined, the command fails with an error. Use `-url` to specify the
registration endpoint explicitly in that case.

## Authentication

Dynamic Client Registration endpoints are usually protected. The command supports two options:

- **Initial access token** — pass `-bearer <token>`. It is sent as `Authorization: Bearer <token>`.
- **HTTP Basic auth** — pass `-client_id` and `-client_secret`. They are sent as `Authorization: Basic ...`.

If neither is provided, the request is sent unauthenticated (only works on open registration endpoints).

## Flags

| Flag | Description | Default |
|---|---|---|
| `-redirect_uris` | Space-separated list of redirect URIs. | `http://localhost:<port>/callback` |
| `-client_name` | Human-readable client name. | `openid-client` |
| `-grant_types` | Space-separated grant types. | `authorization_code client_credentials refresh_token password urn:ietf:params:oauth:grant-type:jwt-bearer` |
| `-response_types` | Space-separated response types. | omitted |
| `-token_endpoint_auth_method` | Token endpoint authentication method. | `client_secret_basic` |
| `-jwks_uri` | URL of the client's JSON Web Key Set. When set, `token_endpoint_auth_method` is forced to `private_key_jwt`. | omitted |
| `-bearer` | Initial access token for the protected registration endpoint. | — |
| `-url` | Registration endpoint override (used when discovery is not available). | — |

## Examples

### Register a confidential client with an initial access token

```bash
openid-client register \
  -issuer https://<tenant>.accounts.ondemand.com \
  -bearer "$INITIAL_ACCESS_TOKEN" \
  -client_name my-app \
  -redirect_uris "https://my-app.example.com/callback https://my-app.example.com/callback2"
```

### Register a client authenticating with client_id / client_secret

```bash
openid-client register \
  -issuer https://<tenant>.accounts.ondemand.com \
  -client_id <admin-client-id> -client_secret <admin-secret> \
  -client_name my-service \
  -grant_types "client_credentials"
```

### Register a client using private_key_jwt (jwks_uri)

When `-jwks_uri` is set, the `token_endpoint_auth_method` is automatically set to `private_key_jwt`.

```bash
openid-client register \
  -issuer https://<tenant>.accounts.ondemand.com \
  -bearer "$INITIAL_ACCESS_TOKEN" \
  -client_name my-jwt-client \
  -jwks_uri "https://my-app.example.com/.well-known/jwks.json"
```

### Provide the registration endpoint directly

```bash
openid-client register \
  -url https://<tenant>.accounts.ondemand.com/oauth2/register \
  -bearer "$INITIAL_ACCESS_TOKEN" \
  -client_name my-app
```

## Response

The command prints the full JSON registration response indented, for example:

```json
{
    "client_id": "11111111-2222-3333-4444-555555555555",
    "client_secret": "generated-secret-value",
    "client_name": "my-app",
    "redirect_uris": [
        "https://my-app.example.com/callback"
    ],
    "grant_types": [
        "authorization_code",
        "refresh_token"
    ],
    "token_endpoint_auth_method": "client_secret_basic"
}
```

Add `-v` to see the outgoing request URL and JSON body for troubleshooting.

## Notes

- The default `-client_id` for the `register` command is `T000000` when not provided; override it with
  `-client_id` (or the `OPENID_ID` environment variable) when using Basic authentication.
- The implementation lives in `HandleClientRegistration` in `pkg/client/exchange.go`.

