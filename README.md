 # SAP Cloud Identity Services - openid-client
 
This project provides a command line interface (CLI) to generate OpenID (OIDC) Tokens from an OIDC complaint serverr, mainly created to test new features like PKCE and Public Client support or Private Key JWT. Mainly for IAS compliance tests. However, any other OIDC provider can be used to get tokens.
The API documentation is available here: https://help.sap.com/docs/cloud-identity-services/cloud-identity-services/openid-connect  

The execution will open a port on you localhost machine. Please ensure that this port is usable. In addition, you need to specify the redirect_uri in your OIDC server,
e.g. http://localhost:8080/callback. If you set port 9002, expect redirect_uri http://localhost:9002/callback

### How to build the project

Use the go tool chain to build the binary.
```text
go install github.com/strehle/cmdline-openid-client/openid-client@latest
```

You can also use go with run to execute it like
```text
go run github.com/strehle/cmdline-openid-client/openid-client@latest
```

Another option is to clone the sources and build it from command 
```text
go build openid-client/openid-client.go
```
On an OS with make environment, simply execute
```text
make
```
### How to test
```text
Usage: openid-client <command> <flags>
       This is a CLI to generate tokens from an OpenID Connect (OIDC) complaint server. Create a service provider/application in the OIDC server with call back url:
       http://localhost:<port>/callback and set below flags to get an ID token

Command: (authorization_code is default)
       authorization_code Perform authorization code flow.
       client_credentials Perform client credentials flow.
       password           Perform resource owner flow, also known as password flow.
       token-exchange     Perform OAuth2 Token Exchange (RFC 8693).
       jwt-bearer         Perform OAuth2 JWT Bearer Grant Type.
       saml-bearer        Perform OAuth2 SAML 2.0 Bearer Grant Type.
       passcode           Retrieve user passcode from X509 user authentication.
       version            Show version.
       help               Show this help for more details.

Flags:
      -issuer           IAS. Default is https://<tenant>.accounts.ondemand.com; XSUAA Default is: https://uaa.cf.eu10.hana.ondemand.com/oauth/token
      -url              Generic endpoint for request. Used if issuer is not OIDC complaint with support of discovery endpoint.
      -client_id        OIDC client ID. This is a mandatory flag.
      -client_secret    OIDC client secret. This is an optional flag and only needed for confidential clients.
      -client_tls       P12 file for client mTLS authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.
      -client_jwt       P12 file for private_key_jwt authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.
      -client_jwt_key   Private Key in PEM for private_key_jwt authentication. Use this parameter together with -client_jwt_kid. Replaces -client_jwt and -pin.
      -client_jwt_kid   Key ID for private_key_jwt authentication. Use this parameter together with -client_jwt_key. Replaces -client_jwt and -pin, use value or path to X509 certificate.
      -client_jwt_x5t   Header for private_key_jwt X509 authentication. Use this parameter together with -client_jwt_key. Replaces -client_jwt and -pin, use value or path to X509 certificate.
      -client_assertion External client token to perform client authentication. Use this parameter instead of client_jwt or client_jwt_key parameters.
      -assertion        Input token for token exchanges, e.g. jwt-bearer and token-exchange.
      -scope            OIDC scope parameter. This is an optional flag, default is openid. If you set none, the parameter scope will be omitted in request.
      -refresh          Bool flag. Default false. If true, call refresh flow for the received id_token.
      -idp_token        Bool flag. Default false. If true, call the OIDC IdP token exchange endpoint (IAS specific only) and return the response.
      -idp_scope        OIDC scope parameter. Default no scope is set. If you set the parameter idp_scope, it is set in IdP token exchange endpoint (IAS specific only).
      -refresh_expiry   Value in seconds. Optional parameter to reduce Refresh Token Lifetime.
      -token_format     Format for access_token. Possible values are opaque and jwt. Optional parameter, default: opaque
      -app_tid          Optional parameter for IAS multi-tenant applications.
      -cmd              Single command to be executed. Supported commands currently: jwks, client_credentials, password
      -pin              PIN to P12/PKCS12 file using -client_tls or -client_jwt
      -port             Callback port. Open on localhost a port to retrieve the authorization code. Optional parameter, default: 8080
      -login_hint       Request parameter login_hint passed to the Corporate IdP.
      -user_tls         P12 file for user mTLS authentication. The parameter is needed for the passcode command.
      -username         User name for command password grant required, else optional.
      -password         User password for command password grant required, else optional.
      -subject_type     Token-Exchange subject type. Type of input assertion.
      -resource         Token-Exchange custom resource parameter.
      -requested_type   Token-Exchange requested type.
      -provider_name    Provider name for token-exchange.
      -k                Skip TLS server certificate verification.
      -v                Verbose. Show more details about calls.
      -h                Show this help for more details.
```
