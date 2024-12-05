# Token-Exchanges in OAuth2/OIDC

The standards are 

* JWT Bearer for authorization grants, e.g. [RFC7523, section 2.1](https://www.rfc-editor.org/info/rfc7523)
* Token Exchange, a generic standard according [RFC8693](https://www.rfc-editor.org/info/rfc8693)

The JWT bearer flow can be used to provide user principal propagation for ID-Tokens from an external system to SCI or
from one application to another. SCI supports for internal user principal propagation the JWT bearer grant with an opaque access token.
This was created before the token-exchange grant was added.

The generic token-exchange grant type (RFC 8693) is supporting more types of incoming and outgoing token types. They are
defined with subject_token_type and requested_token_type.

Hint: The term access_token means in context of SCI an opaque access token. ID tokens are by definition JWT only. Therefore, there is
a token type jwt, which support generic meaning of Json Web Tokens, either a JWT access token or an ID token.

The API for token-exchange is documented in
https://help.sap.com/docs/cloud-identity-services/cloud-identity-services/configure-client-to-call-identity-authentication-token-exchange

New parameters combined with documentation:

* assertion -> subject_token
* subject_type -> subject_token_type ( only last part needed, access_token, id_token, refresh_token, jwt, saml2-session)
* requested_type -> requested_token_type ( only last part needed, access_token, id_token, saml2, saml2-header)
* provider_name -> resource parameter with provider name from https://help.sap.com/docs/cloud-identity-services/cloud-identity-services/consume-apis-from-other-applications
* resource -> resource custom parameter, useful in case of additional information needed, e.g. recipient for saml2-header type

Additional parameter hints:
* token_format -> not new, but with this parameter you can get either a JWT based access token or an opaque one
* login_hint -> useful in case of conditional authentication. 
* client_tls / client_jwt -> The token exchange requires a client authentication, but this can be key based, so that you can replace client_secret

Example 1:

`openid-client -issuer https://<ias-host-name> -client_secret <ias-secret> -client_id <ias-client id> -requested_type saml2 -provider_name <name of API, e.g. SSO> -login_hint <user attribute>`

With this call you get a browser window opened in order to login, either on IAS local or on your corporate IdP (depends on IAS conditional authentication), e.g.

1. Login and create authorization code
2. IAS ID token created from authorization code
3. SAML Bearer token is returned as exchanged result 
4. Use token to perform standard SAML2-Bearer, exchange it into a token for local access 

Example 2 (https://me.sap.com/notes/2043039):

`openid-client -issuer https://<ias-host-name> -client_secret <ias-secret> -client_id <ias-client id> -requested_type saml2-header -provider_name <name of API, e.g. SSO> -login_hint <user attribute> -resource <http endpoint the token should be consumed>`

With this call you get a browser window opened in order to login, either on IAS local or on your corporate IdP (depends on IAS conditional authentication), e.g.

1. Login and create authorization code
2. IAS ID token created from authorization code
3. SAML token is returned as exchanged result 
4. Use token to set in HTTP header when calling a remote system resource. Hint: the receiving system must match conditions from https://me.sap.com/notes/2043039
