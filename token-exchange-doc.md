# Token-Exchanges in OAuth2/OIDC

The standards are 

* JWT Bearer for authorization grants, e.g. [RFC7523, section 2.1](https://www.rfc-editor.org/info/rfc7523)
* Token Exchange, a generic standard according [RFC8693](https://www.rfc-editor.org/info/rfc8693)

The JWT bearer flow is mainly used to provide principal propagation for ID-Tokens from an external system and
from one application to another.

The generic token-exchange grant type is supporting more types of incoming and outgoing token types. They are
defined with subject_token_type and requested_token_type.

The API for token-exchange is documented in
https://help.sap.com/docs/cloud-identity-services/cloud-identity-services/configure-client-to-call-identity-authentication-token-exchange

New parameters combined with documentation:

* assertion -> subject_token
* subject_type -> subject_token_type ( only last part needed, access_token, id_token, refresh_token, jwt)
* requested_type -> requested_token_type ( only last part needed, access_token, id_token, saml2)
* provider_name -> resource parameter with provider name from https://help.sap.com/docs/cloud-identity-services/cloud-identity-services/consume-apis-from-other-applications

Example:

`openid-client -issuer https://<ias-host-name> -client_secret <ias-secret> -client_id <ias-client id> -requested_type saml2 -provider_name <name of API, e.g. SSO> -login_hint <user attribute>`

With this call you get a browser windows opened, then

1. Login (if corp.IdP is enabled, login to corp.IdP)
2. IAS id-token created
3. SAML Bearer token is returned

