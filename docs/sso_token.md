# SSO Token Flow

The SSO token flow is an IAS-specific feature that enables creating new web browser sessions using an opaque one-time token. This is particularly useful for mobile applications or scenarios where you want to seamlessly transition from a command-line authenticated session to a web browser session.

## Overview

The `sso_token` parameter is an opaque, one-time use token that can be used to establish a new authenticated web session in IAS. This flow bridges the gap between different authentication contexts, allowing users to:

- Start with a programmatic authentication (e.g., OAuth2 flows)
- Obtain an SSO token through token exchange
- Open a browser with an authenticated session using that token

This is particularly useful for:
- **Mobile Applications**: Enabling users to continue their session in a browser
- **Desktop Applications**: Opening web-based features after CLI authentication
- **Testing & Development**: Quickly opening authenticated browser sessions
- **Cross-Platform Workflows**: Seamlessly moving between different client types

## How It Works

The SSO token flow consists of two main steps:

### Step 1: Obtain an SSO Token

You first need to obtain an opaque SSO token through token exchange with the special resource parameter `urn:sap:identity:sso`:

```
Token Exchange Request:
- subject_token: An existing token (access_token, id_token, etc.)
- subject_token_type: Type of the subject token
- requested_token_type: urn:ietf:params:oauth:token-type:access_token
- resource: urn:sap:identity:sso
```

This returns an opaque access token that serves as the SSO token.

### Step 2: Use the SSO Token to Open a Browser Session

The SSO token is then used with the `/saml2/idp/sso` endpoint to establish a web session:

```
GET {issuer}/saml2/idp/sso?sso_token={token}&redirect_uri={redirect}
```

The tool automatically opens this URL in the default browser, creating an authenticated session.

## Commands

### Command 1: `sso` - Direct SSO Session Opening

Opens a browser with an authenticated session using a pre-obtained SSO token.

#### Syntax

```bash
openid-client sso -issuer <ISSUER> -sso_token <TOKEN> -redirect_uri <REDIRECT> [-sp <SP_NAME>]
```

#### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `sso` | Yes | The command to execute SSO flow |
| `-issuer` | Yes | The IAS issuer URL |
| `-sso_token` | Yes | The opaque one-time SSO token |
| `-redirect_uri` | Yes | The URL to redirect to after authentication |
| `-sp` | No | Service provider name (optional parameter) |

#### Example

```bash
# Assuming you already have an SSO token
openid-client sso \
  -issuer https://mytenant.accounts.ondemand.com \
  -sso_token "abc123opaqueSsoTokenValue" \
  -redirect_uri "https://myapp.example.com/home"
```

This command will:
1. Construct the SSO URL: `{issuer}/saml2/idp/sso?sso_token=...&redirect_uri=...`
2. Open the URL in the default browser
3. IAS validates the token and creates a web session
4. The browser is redirected to the specified redirect_uri

### Command 2: Authorization Code Flow with SSO Token

You can also use the `sso_token` parameter directly in the authorization code flow to enhance the authentication process.

#### Syntax

```bash
openid-client [authorization_code] -issuer <ISSUER> -client_id <CLIENT_ID> -sso_token <TOKEN> [other parameters]
```

#### Example

```bash
openid-client \
  -issuer https://mytenant.accounts.ondemand.com \
  -client_id my-client-id \
  -sso_token "existing-sso-token" \
  -scope openid
```

The `sso_token` parameter is added to the authorization request as a query parameter.

## Complete Workflow: Obtaining and Using SSO Token

### Workflow 1: Using Authorization Code Flow with `-sso` Flag

The easiest way to obtain and use an SSO token is through OIDC authentication with the `-sso` flag:

```bash
# Step 1: Obtain an SSO token via interactive authorization code flow
# Example: Authorization code flow with SSO token exchange
SSO_TOKEN=$(openid-client authorization_code \
  -issuer https://mytenant.accounts.ondemand.com \
  -client_id my-client-id \
  -client_secret my-client-secret \
  -sso)

# Step 2: Use the SSO token to open browser session
openid-client sso \
  -issuer https://mytenant.accounts.ondemand.com \
  -sso_token "$SSO_TOKEN" \
  -redirect_uri "https://myapp.example.com/home"
```

### Workflow 2: Manual Token Exchange

Alternatively, you can manually specify the SSO resource parameter:

```bash
# Step 1: Authenticate and get a token
ID_TOKEN=$(openid-client authorization_code \
  -issuer https://mytenant.accounts.ondemand.com \
  -client_id my-client-id \
  -scope openid \
  -export id_token)

# Step 2: Exchange for SSO token with explicit resource parameter
SSO_TOKEN=$(openid-client token-exchange \
  -issuer https://mytenant.accounts.ondemand.com \
  -client_id my-client-id \
  -client_secret my-client-secret \
  -token "$ID_TOKEN" \
  -subject_type id_token \
  -requested_type access_token \
  -resource "urn:sap:identity:sso" \
  -export access_token)

# Step 3: Open browser session with SSO token
openid-client sso \
  -issuer https://mytenant.accounts.ondemand.com \
  -sso_token "$SSO_TOKEN" \
  -redirect_uri "https://myapp.example.com/dashboard"
```

### Workflow 3: JWT Bearer with SSO

You can also obtain SSO tokens using JWT bearer grant. The JWT for the 1st step can be a token from local IAS or from a remote corporate IdP:

```bash
# Step 1: Get SSO token via JWT bearer with -sso flag
SSO_TOKEN=$(openid-client jwt-bearer \
  -issuer https://mytenant.accounts.ondemand.com \
  -client_id my-client-id \
  -client_secret my-client-secret \
  -assertion "$EXISTING_JWT_TOKEN" \
  -sso \
  -export access_token)

# Step 2: Open browser session
openid-client sso \
  -issuer https://mytenant.accounts.ondemand.com \
  -sso_token "$SSO_TOKEN" \
  -redirect_uri "https://myapp.example.com"
```

## Complete Script Example

Here's a complete script that demonstrates the entire flow:

```bash
#!/bin/bash

# Configuration
ISSUER="https://mytenant.accounts.ondemand.com"
CLIENT_ID="my-client-id"
CLIENT_SECRET="my-client-secret"
USERNAME="my-username"
PASSWORD="my-password"
REDIRECT_URI="https://myapp.example.com/home"

echo "Step 1: Authenticating with password grant..."
ACCESS_TOKEN=$(openid-client password \
  -issuer "$ISSUER" \
  -client_id "$CLIENT_ID" \
  -client_secret "$CLIENT_SECRET" \
  -username "$USERNAME" \
  -password "$PASSWORD" \
  -export access_token)

if [ -z "$ACCESS_TOKEN" ]; then
  echo "ERROR: Failed to get access token"
  exit 1
fi

echo "✓ Access token obtained"

echo "Step 2: Exchanging for SSO token..."
SSO_TOKEN=$(openid-client token-exchange \
  -issuer "$ISSUER" \
  -client_id "$CLIENT_ID" \
  -client_secret "$CLIENT_SECRET" \
  -token "$ACCESS_TOKEN" \
  -subject_type access_token \
  -requested_type access_token \
  -sso \
  -export access_token)

if [ -z "$SSO_TOKEN" ]; then
  echo "ERROR: Failed to get SSO token"
  exit 1
fi

echo "✓ SSO token obtained"

echo "Step 3: Opening browser with authenticated session..."
openid-client sso \
  -issuer "$ISSUER" \
  -sso_token "$SSO_TOKEN" \
  -redirect_uri "$REDIRECT_URI"

echo "✓ Browser opened with authenticated session"
echo "User will be redirected to: $REDIRECT_URI"
```

## API Details

### Token Exchange Endpoint

**Endpoint**: `POST {issuer}/oauth2/token`

**Request Parameters** (for SSO token):
```
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token={existing_token}
subject_token_type=urn:ietf:params:oauth:token-type:{access_token|id_token}
requested_token_type=urn:ietf:params:oauth:token-type:access_token
resource=urn:sap:identity:sso
client_id={client_id}
client_secret={client_secret}
```

**Response**:
```json
{
  "access_token": "opaque-sso-token-string",
  "token_type": "Bearer",
  "expires_in": 300
}
```

The `access_token` in the response is the SSO token to be used in the browser flow.

### SSO Session Endpoint

**Endpoint**: `GET {issuer}/saml2/idp/sso`

**Query Parameters**:
- `sso_token` (required): The opaque SSO token obtained from token exchange
- `redirect_uri` (required): The URL to redirect to after session establishment
- `sp` (optional): Service provider name

**Example URL**:
```
https://mytenant.accounts.ondemand.com/saml2/idp/sso?sso_token=abc123xyz&redirect_uri=https://myapp.example.com/home
```

**Behavior**:
1. IAS validates the SSO token
2. Creates a new web session with browser cookies
3. Redirects the browser to the specified `redirect_uri`
4. The token is consumed (one-time use only)

## The `-sso` Flag Explained

The `-sso` flag is a convenience feature that automatically sets the correct parameters for SSO token exchange:

**When you use `-sso`, the tool automatically:**
- Sets `resource=urn:sap:identity:sso`
- Sets `requested_token_type=urn:ietf:params:oauth:token-type:access_token`
- For JWT bearer: Sets `refresh_expiry=0` and `token_format=opaque`

**Without `-sso` flag:**
```bash
openid-client token-exchange \
  -token "$TOKEN" \
  -subject_type access_token \
  -requested_type access_token \
  -resource "urn:sap:identity:sso"
```

**With `-sso` flag:**
```bash
openid-client token-exchange \
  -token "$TOKEN" \
  -subject_type access_token \
  -requested_type access_token \
  -sso
```

Both are equivalent, but the flag makes it more convenient and ensures correct configuration.

## Platform Support

The `sso` command automatically opens the SSO URL in the default browser based on the operating system:

| Platform | Browser Command |
|----------|-----------------|
| Linux | `xdg-open` |
| Windows | `rundll32 url.dll,FileProtocolHandler` |
| macOS | `open` |

## Security Considerations

1. **One-Time Use**: SSO tokens are single-use only. Once consumed, they cannot be reused
2. **Short-Lived**: SSO tokens typically expire quickly (e.g., 300 seconds)
3. **Opaque Format**: SSO tokens are opaque strings, not JWTs, for security
4. **Secure Transport**: Always use HTTPS for token exchange and SSO endpoints
5. **Token Storage**: Do not store SSO tokens; use them immediately after generation
6. **Redirect URI Validation**: Ensure redirect URIs are properly validated on the IAS side

## Error Handling

### Common Errors

**1. Invalid or Expired SSO Token**
```
HTTP 401 Unauthorized
```
Solution: Generate a new SSO token. SSO tokens expire quickly and are single-use.

**2. Invalid Redirect URI**
```
HTTP 400 Bad Request
```
Solution: Ensure the redirect URI is properly URL-encoded and valid.

**3. Missing Parameters**
```
Error: sso_token parameter is required
```
Solution: Provide the `-sso_token` parameter with a valid token.

**4. Unsupported Platform**
```
unsupported platform
```
Solution: The `sso` command requires Linux, Windows, or macOS to open the browser automatically.

### Debugging

Enable verbose mode to see the full token exchange response:

```bash
openid-client token-exchange \
  -token "$ACCESS_TOKEN" \
  -subject_type access_token \
  -requested_type access_token \
  -sso \
  -v
```

## Limitations

- SSO tokens are IAS-specific and not part of standard OAuth2/OIDC
- Tokens are opaque and cannot be inspected (unlike JWTs)
- Single-use only - cannot be reused after consumption
- Short expiration time (typically 5 minutes)
- Requires supported platform (Linux, Windows, macOS) for automatic browser opening
- The redirect URI must be registered or allowed by IAS

## Related Documentation

- [Token Exchange Documentation](../token-exchange-doc.md)
- [Client Authentication Methods](../client-auth-doc.md)
- [IAS OAuth2 Documentation](https://help.sap.com/docs/cloud-identity-services/cloud-identity-services/openid-connect)

## Implementation Details

The SSO flow implementation:

1. **Token Exchange** 
   - Sends token exchange request with `resource=urn:sap:identity:sso`
   - Returns opaque access token as SSO token

2. **SSO Session Opening** 
   - Constructs URL: `{issuer}/saml2/idp/sso?sso_token=...&redirect_uri=...`
   - Detects platform and uses appropriate browser command
   - Opens URL in default browser

3. **Authorization Code Flow Integration**:
   - `sso_token` parameter can be added to authorization requests
   - Parameter is passed as query parameter to `/oauth2/authorize` endpoint
