# Client Authentication in OIDC

The client authentication in OAuth2 is described in [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3). In this standard
and the successor ones the secret based authentication is the required one and still it is the first choice for many implementations. 
The use of it in enterprise applications can get a problem, escpecially if security policy requires a rotation for such use cases. In the begin
there were not really alternatives, e.g. only a generic description in [other authentication section](https://datatracker.ietf.org/doc/html/rfc6749#section-2.3.2). 

This has changed with OIDC and in the OAuth 2.1 standard. The [other authentication section](https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-10.html#name-other-authentication-method)
descibes here 2 real alternatives for secrets, namely mTLS *RFC8705* and Private Key JWT. These standards support rotation without
disruption and without sharing a secret/private infromation between 2 parties.

## RFC 8705, mTLS

This [RFC standard](https://www.rfc-editor.org/rfc/rfc8705.html) is not part of OIDC but was added later. The approach is mainly known for user authentication and is typically 
used as secure alternative to user name and password. The same authentication is re-used in OIDC to authenticate an OAuth2 client.
IAS supports so called [Certificate Authentication](https://help.sap.com/docs/identity-authentication/identity-authentication/passwordless-authentication#certificate-authentication)
for users. For operations the REST authentication supports also the same, called [API Authentication](https://help.sap.com/docs/identity-authentication/identity-authentication/dev-configure-certificates-for-api-authentication).

Therefore the usage of client certificates for OAuth2 clients is supported in IAS.

Usage
```bash
openid-client -issuer <yourIAS> -client_id 11111111-your-client-11111111 -client_tls ./final_result.p12 -pin Test1234
```

## Private Key JWT

In short, this term means a JWT created from a private key is used to authenticate a client. This standard has 2 approaches

* OAuth2 with [RFC7523](https://www.rfc-editor.org/info/rfc7523)
* OIDC with client authentication method [private_key_jwt](https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication)

Remark: This tool here generates client JWT only for the OIDC standard. IAS supports both standards. To know what your server supports is therefore
important. In general OIDC includes OAuth2, therefore both standards are valid for an OIDC complaint server, but in real the creation of the used
JWT is different in its claims and because of simplicity this tool supports the easier one, which is OIDC.

The usage for OIDC complaint usage
```bash
openid-client -issuer <yourIAS> -client_id 11111111-your-client-11111111 -client_jwt ./final_result.p12 -pin Test1234
```

### Pro and Cons between both standards

The pro and cons depend not on the protocol, but on the infrastructure which is used to support them. In most cloud environments the TLS termination
is done in proxies or load balancers in front of the OAuth2/OIDC server. This is the case for IAS and for (XS)UAA in CF. The mTLS used X509 certificate
is then set into a header varible and transported to the authentication server. The termination component (proxy/load balancer) has no knowledge about
the mappings but typically allow most often only CA signed certificates. This makes it hard to supported generic mTLS.

In IAS the applications allow to generate a P12 in section client authentication. These P12 files contain CA signed certificates and therefore they
can be used with this tool. 

#### mTLS

##### Pro
* Easy to support in client compontents, e.g. curl, client REST frameworks. They all support X509 authentication and therefore a setup on client side is easy.
##### Cons
* CA signed certificates are needed. Customers can have their own CA and register then their CA, but this is extra effort.

#### Private Key JWT

##### Pro
* The mapping in IAS is easy, either with extra mapped certificate or JWKS_URI.
* Self-Signed/Self-created certificates can be used
##### Cons
* There are not much clients which support this standard, therefore this tool was created for.

### Howto Use the Private Key only for Private Key JWT

1. Optional create key pairs and X509 certificate
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=DE/ST=BW/L=Walldorf/O=SAP/OU=Security/CN=localhost"
```

2. Use the private key for client authentication
```bash
openid-client -issuer <yourIAS> -client_id 11111111-your-client-11111111 -client_jwt_kid ./key.pem -client_jwt_kid key-id-1
```

### Howto setup PKCS12 Key+Certificate for Private Key JWT 

1. Optional create key pairs and X509 certificate
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=DE/ST=BW/L=Walldorf/O=SAP/OU=Security/CN=localhost"
```

2. Convert the key and certificate into a P12 and set a transport pin.
```bash
openssl pkcs12 -export -legacy -inkey key.pem -in cert.pem -out final_result.p12 -passout pass:Test1234
```

3. Upload the cert.pem file or content to the IAS application

`https://help.sap.com/docs/identity-authentication/identity-authentication/dev-configure-certificates-for-api-authentication
`

4. Use the P12 for client authentication
```bash
openid-client -issuer <yourIAS> -client_id 11111111-your-client-11111111 -client_jwt ./final_result.p12 -pin Test1234
```

### IAS OIDC
https://help.sap.com/docs/identity-authentication/identity-authentication/openid-connect