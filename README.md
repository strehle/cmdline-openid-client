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
       passcode           Retrieve user passcode from X509 user authentication. Need user_tls for user authentication.
       idp_token          Retrieve trusted IdP token. Need assertion for user trust and client authentication.
       introspect         Perform OAuth2 Introspection Endpoint Call. Need token input parameter.
       sso                Perform sso token flow to create a new web session in IAS.
       version            Show version.
       help               Show this help for more details.

Flags:
      -issuer           IAS. Default is https://<tenant>.accounts.ondemand.com; XSUAA Default is: https://uaa.cf.eu10.hana.ondemand.com/oauth/token
      -url              Generic endpoint for request. Used if issuer is not OIDC complaint with support of discovery endpoint.
      -cf               Simulate cf command client. Use cf config.json for OIDC endpoints and store result after call. Allow to perform direct UAA actions and use of token in cf itself.
      -client_id        OIDC client ID. This is a mandatory flag.
      -client_secret    OIDC client secret. This is an optional flag and only needed for confidential clients.
      -client_tls       P12 file for client mTLS authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.
      -client_jwt       P12 file for private_key_jwt authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.
      -client_jwt_key   Private Key in PEM for private_key_jwt authentication. Use this parameter together with -client_jwt_kid. Replaces -client_jwt and -pin.
      -client_jwt_kid   Key ID for private_key_jwt authentication. Use this parameter together with -client_jwt_key. Replaces -client_jwt and -pin, use value or path to X509 certificate.
      -client_jwt_x5t   Header for private_key_jwt X509 authentication. Use this parameter together with -client_jwt_key. Replaces -client_jwt and -pin, use value or path to X509 certificate.
      -client_assertion External client token to perform client authentication. Use this parameter instead of client_jwt or client_jwt_key parameters.
      -bearer           Own token to perform client API authentication. The value will be set in authorization header as bearer value.
      -assertion        Input token for token exchanges, e.g. jwt-bearer or token-exchange and other token information endpoints.
      -scope            OIDC scope parameter. This is an optional flag, default is openid. If you set none, the parameter scope will be omitted in request.
      -nonce            OIDC nonce parameter. This is an optional flag. If you do not set it, the parameter will be omitted in request.
      -prompt           OIDC prompt parameter. This is an optional parameter. If you do not set it, the parameter will be omitted in request. Value can be none or login.
      -max_age          OIDC max_age parameter. This is an optional parameter. If you do not set it, the parameter will be omitted in request.
      -refresh          Bool flag. Default false. If true, call refresh flow for the received id_token.
      -idp_token        Bool flag. Default false. If true, call the OIDC IdP token exchange endpoint (IAS specific only) and return the response.
      -idp_scope        OIDC scope parameter. Default no scope is set. If you set the parameter idp_scope, it is set in IdP token exchange endpoint (IAS specific only).
      -introspect       Bool flag. Default false. If true, call the OIDC token introspect endpoint (if provided in well-known) and return the response.
      -refresh_expiry   Value in seconds. Optional parameter to reduce Refresh Token Lifetime.
      -token            Input token for token introspect and token-exchange calls.
      -token_format     Format for access_token. Possible values are opaque and jwt. Optional parameter, default: opaque
      -app_tid          Optional parameter for IAS multi-tenant applications.
      -cmd              Single command to be executed. Supported commands currently: jwks, client_credentials, password
      -pin              PIN to P12/PKCS12 file using -client_tls or -client_jwt
      -port             Callback port. Open on localhost a port to retrieve the authorization code. Optional parameter, default: 8080
      -login_hint       Request parameter login_hint passed to the Corporate IdP.
      -origin           Use for UAA only. Create login_hint parameter for cf simulation calls.
      -user_tls         P12 file for user mTLS authentication. The parameter is needed for the passcode command.
      -username         User name for command password grant required, else optional.
      -password         User password for command password grant required, else optional.
      -subject_type     Token-Exchange subject type. Type of input assertion.
      -resource         Token-Exchange custom resource parameter.
      -requested_type   Token-Exchange requested type.
      -redirect_uri     Redirect URL for the sso command only.
      -sp               Service provider name parameter for sso command only.
      -sso              Use sso resource flow. Set true to get static parameter resource=urn:sap:identity:sso. Useful only in token-exchange.
      -sso_token        Opaque one time token to create a web session in IAS. Useful only in commands sso and authorization_code.
      -provider_name    Provider name for token-exchange.
      -k                Skip TLS server certificate verification and skip OIDC issuer check from well-known.
      -v                Verbose. Show more details about calls.
      -h                Show this help for more details.
```

### How to test in automation without showing secrets
In environments with outlog to logs or others it might be needed to hide the secrets and/or client details.
There are some environment variables, which will be used if set. A variable passed to the command itself always as prio before the
environment, but you can also mix input parameters and environment.

* OPENID_ISSUER The issuer of the OIDC server. Useful if you re-use a command often to omit it from a command. 
* OPENID_ID The client_id parameter.
* OPENID_SECRET The client_secret parameter.
* OPENID_FORMAT The format of the access_token. Possible values are jwt or opaque.

Example
```text
openid-client client_credentials
```
or with some information
```text
openid-client client_credentials -client_id xxxxx
```