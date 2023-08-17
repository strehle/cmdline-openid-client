 # SAP IAS openid-commandline-client
It is a CLI to generate OpenID TD Token from an OpenID Connect (OIDC) complaiant server, mainly created to test PKCE and Public Client support, like SAP IAS provides it. However any other OIDC provider can be used to get tokens.

The execution will open a port on you localhost machine. Please ensure that this port is usable. In additon, you need to specify the redirect_uri in your OIDC server,
e.g. http://localhost:8080/callback. If you set port 9002, expect redirect_uri http://localhost:9002/callback

### How to build the project

Use the go tool chain to build the binary.
```text
go build cmd/openid-client.go
```
### How to test
```text
./openid-client -help
Usage: openid-client
       This is a CLI to generate tokens from an OpenID Connect (OIDC) complaiant server. Create a service provider/application in the OIDC server with call back url:
       http://localhost:<port>/callback and set below flags to get an ID token
Flags:
      -issuer           IAS. Default is https://<yourtenant>.accounts.ondemand.com; XSUAA Default is: https://uaa.cf.eu10.hana.ondemand.com/oauth/token
      -client_id        OIDC client ID. This is a mandatory flag.
      -client_secret    OIDC client secret. This is an optional flag and only needed for confidential clients.
      -client_tls       P12 file for client mTLS authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.
      -client_jwt       P12 file for private_key_jwt authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.
      -scope            OIDC scope parameter. This is an optional flag, default is openid. If you set none, the parameter scope will be omitted in request.
      -refresh          Bool flag. Default false. If true, call refresh flow for the received id_token.
      -idp_token        Bool flag. Default false. If true, call the OIDC IdP token exchange endpoint (IAS specific only) and return the response.
      -idp_scope        OIDC scope parameter. Default no scope is set. If you set the parameter idp_scope, it is set in IdP token exchange endpoint (IAS specific only).
      -refresh_expiry   Value in seconds. Optional parameter to reduce Refresh Token Lifetime.
      -token_format     Format for access_token. Possible values are opaque and jwt. Optional parameter, default: opaque
      -pin              PIN to P12/PKCS12 file using -client_tls or -client_jwt
      -port             Callback port. Open on localhost a port to retrieve the authorization code. Optional parameter, default: 8080
      -h                Show this help
``` 
for more details.
