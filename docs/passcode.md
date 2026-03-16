# IAS Passcode Service

The passcode service is an SAP Cloud Identity Services (IAS) specific feature that enables users to retrieve a temporary one-time passcode through X.509 certificate-based authentication. This passcode can then be used for password-based authentication flows or other scenarios where a temporary credential is required.

## Overview

The passcode service provides a secure way to obtain a temporary passcode by authenticating with a user X.509 certificate (mTLS). This is particularly useful in scenarios where:

- Users need to authenticate from a command-line interface or automation scripts
- Certificate-based authentication is available but password-based flows are required downstream
- A temporary credential is needed for testing or development purposes

The service endpoint returns a short-lived passcode that can be used as a password credential.

## How It Works

The passcode flow follows these steps:

1. The client presents a user X.509 certificate for mTLS authentication
2. The client makes a GET request to the `/service/users/passcode` endpoint
3. IAS validates the certificate and authenticates the user
4. The server returns a JSON response containing the temporary passcode
5. The passcode can be used immediately for authentication flows

### Dual Certificate Authentication (User + Client mTLS)

A powerful feature of the passcode service is the ability to combine user and client certificate authentication:

**Flow Overview:**
```
1. User mTLS Auth → Passcode Retrieval
   ↓
2. Passcode + Client mTLS Auth → Token Request (Password Grant)
   ↓
3. Result: Access Token with dual certificate security
```

**Security Model:**
- **User Identity**: Verified via user X.509 certificate during passcode retrieval
- **Client Identity**: Verified via client X.509 certificate during token request
- **Authorization**: Passcode acts as proof of user authentication

This approach provides:
- ✓ No shared secrets (no client_secret, no user password)
- ✓ Certificate-based authentication for both user and client
- ✓ Compliance with zero-trust security models
- ✓ Support for certificate rotation without password changes
- ✓ Audit trail for both user and client certificates

## Prerequisites

To use the passcode service, you need:

- An IAS tenant with passcode service enabled
- A valid user X.509 certificate in P12/PKCS12 format
- The certificate PIN/password
- The IAS issuer URL (e.g., `https://<tenant>.accounts.ondemand.com`)

## Command Usage

### Basic Syntax

```bash
openid-client passcode -issuer <IAS_ISSUER> -user_tls <PATH_TO_P12> -pin <PIN>
```

### Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `passcode` | Yes | The command to execute the passcode retrieval |
| `-issuer` | Yes | The IAS issuer URL (must start with `https://`) |
| `-user_tls` | Yes | Path to the P12/PKCS12 file containing the user certificate |
| `-pin` | Yes | PIN/password for the P12 file |
| `-v` | No | Verbose mode - shows detailed response information |
| `-k` | No | Skip TLS certificate verification (for testing only) |

### Examples

#### Basic Passcode Retrieval

```bash
openid-client passcode \
  -issuer https://mytenant.accounts.ondemand.com \
  -user_tls ./user-certificate.p12 \
  -pin MySecurePin123
```

Output:
```
abc123xyz789
```

#### Verbose Mode

To see the full API response including additional metadata:

```bash
openid-client passcode \
  -issuer https://mytenant.accounts.ondemand.com \
  -user_tls ./user-certificate.p12 \
  -pin MySecurePin123 \
  -v
```

Output:
```
Response from Passcode endpoint 
==========
OIDC Response Body
{
    "passcode": "abc123xyz789",
    "expires_in": 300
}
==========
abc123xyz789
```

#### Using Environment Variables

You can set the PIN as an environment variable to avoid exposing it in command history:

```bash
export OPENID_PIN=MySecurePin123

openid-client passcode \
  -issuer https://mytenant.accounts.ondemand.com \
  -user_tls ./user-certificate.p12
```

## API Details

### Endpoint

```
GET {issuer}/service/users/passcode
```

### Authentication

The endpoint requires user authentication via X.509 client certificate (mTLS).

### Request Headers

```
Accept: application/json
User-Agent: OpenId Client/GO/1
```

### Response

**Success Response (HTTP 200)**

```json
{
  "passcode": "temporary-passcode-string",
  "expires_in": 300
}
```

**Response Fields:**

- `passcode` (string): The temporary one-time passcode
- `expires_in` (number, optional): Validity period in seconds

## Integration Examples

### Using the Passcode with Password Grant

Once you have retrieved the passcode, you can use it with the password grant flow:

```bash
# Step 1: Get the passcode
PASSCODE=$(openid-client passcode \
  -issuer https://mytenant.accounts.ondemand.com \
  -user_tls ./user-certificate.p12 \
  -pin MySecurePin123)

# Step 2: Use it in password grant with client secret
openid-client password \
  -issuer https://mytenant.accounts.ondemand.com \
  -client_id my-client-id \
  -client_secret my-client-secret \
  -username my-username \
  -password "$PASSCODE"
```

### Using the Passcode with Password Grant and Client mTLS

You can combine user X.509 authentication (for passcode retrieval) with client X.509 authentication (for the password grant). This provides double X.509 certificate security:

**Option 1: Using separate certificates for user and client**

```bash
# Step 1: Get the passcode using user certificate
PASSCODE=$(openid-client passcode \
  -issuer https://mytenant.accounts.ondemand.com \
  -user_tls ./user-certificate.p12 \
  -pin UserCertPin123)

# Step 2: Use passcode with client certificate for password grant
openid-client password \
  -issuer https://mytenant.accounts.ondemand.com \
  -client_id my-client-id \
  -client_tls ./client-certificate.p12 \
  -pin ClientCertPin456 \
  -username my-username \
  -password "$PASSCODE"
```

**Option 2: Using the same certificate for both user and client (if applicable)**

```bash
# Step 1: Get the passcode
PASSCODE=$(openid-client passcode \
  -issuer https://mytenant.accounts.ondemand.com \
  -user_tls ./combined-certificate.p12 \
  -pin MyCertPin123)

# Step 2: Use the same certificate for client authentication
openid-client password \
  -issuer https://mytenant.accounts.ondemand.com \
  -client_id my-client-id \
  -client_tls ./combined-certificate.p12 \
  -pin MyCertPin123 \
  -username my-username \
  -password "$PASSCODE"
```

**What this achieves:**

1. **User Authentication via mTLS**: The user authenticates with their X.509 certificate to retrieve the passcode
2. **Client Authentication via mTLS**: The OAuth2 client authenticates with its X.509 certificate instead of client secret
3. **User Authorization**: The passcode serves as the user's password credential in the password grant
4. **Double Certificate Security**: Both user and client identities are verified through certificates

This approach is particularly useful when:
- You want to avoid using client secrets
- You need strong authentication for both user and client
- You're implementing certificate-based security policies
- You're automating authentication flows with certificate credentials

### Using in Scripts

**Example 1: Basic passcode retrieval and usage**

```bash
#!/bin/bash

ISSUER="https://mytenant.accounts.ondemand.com"
USER_CERT="./user-certificate.p12"
CERT_PIN="MySecurePin123"

# Retrieve passcode
echo "Retrieving passcode..."
PASSCODE=$(openid-client passcode \
  -issuer "$ISSUER" \
  -user_tls "$USER_CERT" \
  -pin "$CERT_PIN")

if [ -z "$PASSCODE" ]; then
  echo "Failed to retrieve passcode"
  exit 1
fi

echo "Passcode retrieved successfully"
echo "Using passcode for authentication..."

# Use the passcode in your authentication flow
# ... your code here ...
```

**Example 2: Complete certificate-based authentication with password grant**

```bash
#!/bin/bash

# Configuration
ISSUER="https://mytenant.accounts.ondemand.com"
CLIENT_ID="my-client-id"
USERNAME="my-username"
USER_CERT="./user-certificate.p12"
USER_PIN="UserCertPin123"
CLIENT_CERT="./client-certificate.p12"
CLIENT_PIN="ClientCertPin456"

# Step 1: Retrieve passcode using user certificate (mTLS user authentication)
echo "Authenticating with user certificate to retrieve passcode..."
PASSCODE=$(openid-client passcode \
  -issuer "$ISSUER" \
  -user_tls "$USER_CERT" \
  -pin "$USER_PIN")

if [ -z "$PASSCODE" ]; then
  echo "ERROR: Failed to retrieve passcode"
  exit 1
fi

echo "✓ Passcode retrieved successfully"

# Step 2: Perform password grant with client certificate (mTLS client authentication)
echo "Performing password grant with client certificate authentication..."
TOKEN_RESPONSE=$(openid-client password \
  -issuer "$ISSUER" \
  -client_id "$CLIENT_ID" \
  -client_tls "$CLIENT_CERT" \
  -pin "$CLIENT_PIN" \
  -username "$USERNAME" \
  -password "$PASSCODE" \
  -export access_token)

if [ -z "$TOKEN_RESPONSE" ]; then
  echo "ERROR: Failed to get access token"
  exit 1
fi

echo "✓ Access token retrieved successfully"
echo "Token: $TOKEN_RESPONSE"

# Now use the token for API calls
# curl -H "Authorization: Bearer $TOKEN_RESPONSE" https://api.example.com/resource
```

**Example 3: Using the same certificate for both user and client**

```bash
#!/bin/bash

# Configuration
ISSUER="https://mytenant.accounts.ondemand.com"
CLIENT_ID="my-client-id"
USERNAME="my-username"
CERT_FILE="./combined-certificate.p12"
CERT_PIN="MyCertPin123"

# Step 1: Get passcode (user mTLS)
echo "Step 1: Retrieving passcode with certificate authentication..."
PASSCODE=$(openid-client passcode \
  -issuer "$ISSUER" \
  -user_tls "$CERT_FILE" \
  -pin "$CERT_PIN")

[ -z "$PASSCODE" ] && echo "ERROR: Passcode retrieval failed" && exit 1
echo "✓ Passcode retrieved"

# Step 2: Get access token using passcode and same certificate (client mTLS)
echo "Step 2: Getting access token with certificate authentication..."
ACCESS_TOKEN=$(openid-client password \
  -issuer "$ISSUER" \
  -client_id "$CLIENT_ID" \
  -client_tls "$CERT_FILE" \
  -pin "$CERT_PIN" \
  -username "$USERNAME" \
  -password "$PASSCODE" \
  -export access_token)

[ -z "$ACCESS_TOKEN" ] && echo "ERROR: Token retrieval failed" && exit 1
echo "✓ Access token retrieved"

# Use the token
echo "Access Token: ${ACCESS_TOKEN:0:50}..."
```

## Error Handling

### Common Errors

**1. Missing or Invalid Certificate**

```
Error: user_tls parameter is required in order to execute passcode
```

Solution: Provide a valid P12 file path using the `-user_tls` parameter.

**2. Invalid Issuer**

```
Error: issuer with https schema is required to run this command
```

Solution: Ensure the issuer URL starts with `https://`.

**3. Certificate Authentication Failed**

If the server returns an error (non-200 status), the tool will display the error response from the server. Common causes:
- Invalid or expired certificate
- Certificate not registered for the user
- User account disabled or locked

**4. Wrong PIN**

```
Error: decode pkcs12 failed
```

Solution: Verify the PIN/password for your P12 file is correct.

## Security Considerations

1. **Certificate Protection**: Keep your user certificate P12 file secure with appropriate file permissions
2. **PIN Management**: Never hardcode PINs in scripts; use environment variables or secure secret management
3. **Passcode Lifetime**: The passcode is typically short-lived; use it immediately after retrieval
4. **HTTPS Required**: The endpoint requires HTTPS to ensure secure transmission
5. **Certificate Validity**: Ensure your certificate is not expired and is properly registered with IAS

## Limitations

- The passcode service is IAS-specific and not available on all OIDC providers
- Passcodes are single-use or time-limited credentials
- User must have a valid X.509 certificate registered in IAS
- The `-client_id` parameter is optional for this command (defaults to "T000000" if not provided)

## Differences from Other Authentication Methods

| Method | Authentication | Output | Use Case |
|--------|---------------|--------|----------|
| Passcode | User mTLS | Temporary passcode string | Obtain credential for password flows |
| Passcode + Client mTLS | User mTLS + Client mTLS | Access token + ID token | Certificate-only authentication (no secrets) |
| Password Grant | Username + Password | Access token + ID token | Direct token acquisition |
| Password Grant + Client mTLS | Username + Password + Client mTLS | Access token + ID token | Password auth with certificate client |
| Client Credentials | Client secret/cert | Access token | Service-to-service authentication |
| Authorization Code | User browser login | Access token + ID token | Interactive user authentication |

## Related Documentation

- [Client Authentication Methods](client-auth-doc.md)
- [IAS API Authentication](https://help.sap.com/docs/identity-authentication/identity-authentication/dev-configure-certificates-for-api-authentication)
- [Certificate Authentication](https://help.sap.com/docs/identity-authentication/identity-authentication/passwordless-authentication#certificate-authentication)

## Troubleshooting

### Enable Verbose Mode

Always start troubleshooting by enabling verbose mode with `-v`:

```bash
openid-client passcode \
  -issuer https://mytenant.accounts.ondemand.com \
  -user_tls ./user-certificate.p12 \
  -pin MySecurePin123 \
  -v
```

This will show:
- Full HTTP response from the server
- Response body in formatted JSON
- Any error messages or warnings

### Verify Certificate

Ensure your P12 file is valid and contains the correct certificate:

```bash
# Extract certificate info
openssl pkcs12 -in user-certificate.p12 -info -noout
```

### Test Connection

Use the `-k` flag to test connectivity (disable TLS verification):

```bash
openid-client passcode \
  -issuer https://mytenant.accounts.ondemand.com \
  -user_tls ./user-certificate.p12 \
  -pin MySecurePin123 \
  -k \
  -v
```

**Note**: Only use `-k` for testing/debugging, never in production.

## Implementation Details

The passcode command internally:

1. Loads the P12 certificate and configures the TLS client for mTLS
2. Makes a GET request to `{issuer}/service/users/passcode`
3. Sets appropriate headers (Accept: application/json, User-Agent)
4. Parses the JSON response to extract the passcode value
5. Outputs the passcode to stdout (or full response in verbose mode)

The implementation can be found in:
- Command handling: `openid-client/openid-client.go` (lines ~598-609)
- Service function: `pkg/client/exchange.go` (`HandlePasscode` function)
