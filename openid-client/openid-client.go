package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/strehle/cmdline-openid-client/pkg/cf"
	"github.com/strehle/cmdline-openid-client/pkg/client"
	"golang.org/x/net/context"
	"software.sslmate.com/src/go-pkcs12"
)

var (
	version = "dev"
	commit  = "0"
	date    = "unknown"
)

func main() {
	flag.Usage = func() {
		fmt.Println("Usage: openid-client <command> <flags>\n" +
			"       This is a CLI to generate tokens from an OpenID Connect (OIDC) complaint server. Create a service provider/application in the OIDC server with call back url:\n" +
			"       http://localhost:<port>/callback and set below flags to get an ID token\n" +
			"\nCommand: (authorization_code is default)\n" +
			"       authorization_code Perform authorization code flow.\n" +
			"       client_credentials Perform client credentials flow.\n" +
			"       password           Perform resource owner flow, also known as password flow.\n" +
			"       token-exchange     Perform OAuth2 Token Exchange (RFC 8693).\n" +
			"       jwt-bearer         Perform OAuth2 JWT Bearer Grant Type.\n" +
			"       saml-bearer        Perform OAuth2 SAML 2.0 Bearer Grant Type.\n" +
			"       passcode           Retrieve user passcode from X509 user authentication. Need user_tls for user authentication.\n" +
			"       idp_token          Retrieve trusted IdP token. Need assertion for user trust and client authentication.\n" +
			"       introspect         Perform OAuth2 Introspection Endpoint Call. Need token input parameter.\n" +
			"       version            Show version.\n" +
			"       help               Show this help for more details.\n" +
			"\n" +
			"Flags:\n" +
			"      -issuer           IAS. Default is https://<tenant>.accounts.ondemand.com; XSUAA Default is: https://uaa.cf.eu10.hana.ondemand.com/oauth/token\n" +
			"      -url              Generic endpoint for request. Used if issuer is not OIDC complaint with support of discovery endpoint.\n" +
			"      -cf               Simulate cf command client. Use cf config.json for OIDC endpoints and store result after call. Allow to perform direct UAA actions and use of token in cf itself.\n" +
			"      -client_id        OIDC client ID. This is a mandatory flag.\n" +
			"      -client_secret    OIDC client secret. This is an optional flag and only needed for confidential clients.\n" +
			"      -client_tls       P12 file for client mTLS authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.\n" +
			"      -client_jwt       P12 file for private_key_jwt authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.\n" +
			"      -client_jwt_key   Private Key in PEM for private_key_jwt authentication. Use this parameter together with -client_jwt_kid. Replaces -client_jwt and -pin.\n" +
			"      -client_jwt_kid   Key ID for private_key_jwt authentication. Use this parameter together with -client_jwt_key. Replaces -client_jwt and -pin, use value or path to X509 certificate.\n" +
			"      -client_jwt_x5t   Header for private_key_jwt X509 authentication. Use this parameter together with -client_jwt_key. Replaces -client_jwt and -pin, use value or path to X509 certificate.\n" +
			"      -client_assertion External client token to perform client authentication. Use this parameter instead of client_jwt or client_jwt_key parameters.\n" +
			"      -bearer           Own token to perform client API authentication. The value will be set in authorization header as bearer value.\n" +
			"      -assertion        Input token for token exchanges, e.g. jwt-bearer or token-exchange and other token information endpoints.\n" +
			"      -scope            OIDC scope parameter. This is an optional flag, default is openid. If you set none, the parameter scope will be omitted in request.\n" +
			"      -nonce            OIDC nonce parameter. This is an optional flag. If you do not set it, the parameter will be omitted in request.\n" +
			"      -prompt           OIDC prompt parameter. This is an optional parameter. If you do not set it, the parameter will be omitted in request. Value can be none or login.\n" +
			"      -max_age          OIDC max_age parameter. This is an optional parameter. If you do not set it, the parameter will be omitted in request. \n" +
			"      -refresh          Bool flag. Default false. If true, call refresh flow for the received id_token.\n" +
			"      -idp_token        Bool flag. Default false. If true, call the OIDC IdP token exchange endpoint (IAS specific only) and return the response.\n" +
			"      -idp_scope        OIDC scope parameter. Default no scope is set. If you set the parameter idp_scope, it is set in IdP token exchange endpoint (IAS specific only).\n" +
			"      -introspect       Bool flag. Default false. If true, call the OIDC token introspect endpoint (if provided in well-known) and return the response.\n" +
			"      -refresh_expiry   Value in seconds. Optional parameter to reduce Refresh Token Lifetime.\n" +
			"      -token            Input token for token introspect and token-exchange calls.\n" +
			"      -token_format     Format for access_token. Possible values are opaque and jwt. Optional parameter, default: opaque\n" +
			"      -app_tid          Optional parameter for IAS multi-tenant applications.\n" +
			"      -cmd              Single command to be executed. Supported commands currently: jwks, client_credentials, password\n" +
			"      -pin              PIN to P12/PKCS12 file using -client_tls or -client_jwt \n" +
			"      -port             Callback port. Open on localhost a port to retrieve the authorization code. Optional parameter, default: 8080\n" +
			"      -login_hint       Request parameter login_hint passed to the Corporate IdP.\n" +
			"      -origin           Use for UAA only. Create login_hint parameter for cf simulation calls.\n" +
			"      -user_tls         P12 file for user mTLS authentication. The parameter is needed for the passcode command.\n" +
			"      -username         User name for command password grant required, else optional.\n" +
			"      -password         User password for command password grant required, else optional.\n" +
			"      -subject_type     Token-Exchange subject type. Type of input assertion.\n" +
			"      -resource         Token-Exchange custom resource parameter.\n" +
			"      -requested_type   Token-Exchange requested type.\n" +
			"      -provider_name    Provider name for token-exchange.\n" +
			"      -k                Skip TLS server certificate verification.\n" +
			"      -v                Verbose. Show more details about calls.\n" +
			"      -h                Show this help for more details.")
	}

	var issEndPoint = flag.String("issuer", "", "OIDC Issuer URI")
	var urlEndPoint = flag.String("url", "", "Generic URL endpoint")
	var doCfCall = flag.Bool("cf", false, "Simulate CF auth command line")
	var clientID = flag.String("client_id", "", "OIDC client ID")
	var clientSecret = flag.String("client_secret", "", "OIDC client secret")
	var doRefresh = flag.Bool("refresh", false, "Refresh the received id_token")
	var isVerbose = flag.Bool("v", false, "Show more details about calls")
	var scopeParameter = flag.String("scope", "", "OIDC scope parameter")
	var nonceParameter = flag.String("nonce", "", "OIDC nonce parameter")
	var promptParameter = flag.String("prompt", "", "OIDC nonce parameter")
	var maxAgeParameter = flag.String("max_age", "", "OIDC nonce parameter")
	var doCorpIdpTokenExchange = flag.Bool("idp_token", false, "Return OIDC IdP token response")
	var doIntrospect = flag.Bool("introspect", false, "Call introspect with received id_token")
	var refreshExpiry = flag.String("refresh_expiry", "", "Value in seconds to reduce Refresh Token Lifetime")
	var tokenFormatParameter = flag.String("token_format", "opaque", "Format for access_token")
	var portParameter = flag.String("port", "8080", "Callback port on localhost")
	var idpScopeParameter = flag.String("idp_scope", "", "Request scope parameter in OIDC IdP token")
	var clientPkcs12 = flag.String("client_tls", "", "PKCS12 file for OIDC client mTLS authentication")
	var clientJwtPkcs12 = flag.String("client_jwt", "", "PKCS12 file for OIDC private_key_jwt authentication")
	var pin = flag.String("pin", "", "PIN to PKCS12 file")
	var clientJwtKey = flag.String("client_jwt_key", "", "Private Key signing the client JWT for private_key_jwt authentication")
	var clientJwtKid = flag.String("client_jwt_kid", "", "Key ID of client JWT for private_key_jwt authentication")
	var clientJwtX5t = flag.String("client_jwt_x5t", "", "X5T Header in client JWT for private_key_jwt authentication")
	var clientAssertion = flag.String("client_assertion", "", "Client assertion JWT for private_key_jwt authentication")
	var bearerToken = flag.String("bearer", "", "The value will be set in authorization header as bearer value")
	var userName = flag.String("username", "", "User name for command password grant required, else optional")
	var userPassword = flag.String("password", "", "User password for command password grant required, else optional")
	var userPkcs12 = flag.String("user_tls", "", "PKCS12 file for user mTLS authentication using passcode command")
	var loginHint = flag.String("login_hint", "", "Parameter login_hint")
	var cfOrigin = flag.String("origin", "", "CF UAA origin")
	var doVersion = flag.Bool("version", false, "Show version")
	var appTid = flag.String("app_tid", "", "Application tenant ID")
	var command = flag.String("cmd", "", "Single command to be executed")
	var assertionToken = flag.String("assertion", "", "Input token for token exchanges")
	var tokenInput = flag.String("token", "", "Input token for token introspect or revoke")
	var subjectType = flag.String("subject_type", "", "Token input type")
	var requestedType = flag.String("requested_type", "", "Token-Exchange requested type")
	var providerName = flag.String("provider_name", "", "Provider name for token-exchange")
	var resourceParam = flag.String("resource", "", "Additional resource")
	var skipTlsVerification = flag.Bool("k", false, "Skip TLS server certificate verification")
	var mTLS = false
	var privateKeyJwt = ""
	var arguments []string
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], "-") == false {
		arguments = os.Args[2:]
		*command = os.Args[1]
	} else {
		arguments = os.Args[1:]
	}
	oidcError := flag.CommandLine.Parse(arguments)
	if oidcError != nil {
		log.Fatal(oidcError)
	}
	switch *command {
	case "jwks":
		*issEndPoint = "https://accounts.sap.com"
	case "help":
		flag.Usage()
		return
	case "version":
		showVersion()
		return
	case "client_credentials", "password", "token-exchange", "jwt-bearer", "saml-bearer", "idp_token", "":
	case "passcode", "introspect":
		if *clientID == "" {
			*clientID = "T000000" /* default */
		}
	case "authorization_code":
		*command = "" /* default command */
	default:
		log.Fatal("Invalid command, see usage (-h)")
	}
	if *command != "jwks" {
		if *doVersion {
			showVersion()
			return
		}
		if *doCfCall {
			var uaaConfig = cf.ReadUaaConfig()
			*issEndPoint = uaaConfig.UAAEndpoint
			*clientID = uaaConfig.UAAOAuthClient
			*clientSecret = uaaConfig.UAAOAuthClientSecret
		}
		if *issEndPoint == "" {
			*issEndPoint = os.Getenv("OPENID_ISSUER")
		}
		if *clientID == "" {
			*clientID = os.Getenv("OPENID_ID")
		}
		if *clientSecret == "" {
			*clientSecret = os.Getenv("OPENID_SECRET")
		}
		if *issEndPoint == "" {
			log.Fatal("issuer is required to run this command")
		} else if *clientID == "" {
			log.Fatal("client_id is required to run this command")
		} else if *clientPkcs12 != "" && *userPkcs12 != "" {
			log.Fatal("client and user TLS cannot be used in parallel")
		}
	}
	var callbackURL = "http://localhost:" + *portParameter + "/callback"
	ctx := context.Background()
	var claims struct {
		AuthorizeEndpoint  string `json:"authorization_endpoint"`
		EndSessionEndpoint string `json:"end_session_endpoint"`
		TokenEndPoint      string `json:"token_endpoint"`
		IntroSpectEndpoint string `json:"introspection_endpoint,omitempty"`
	}
	provider, oidcError := oidc.NewProvider(ctx, *issEndPoint)
	if oidcError != nil {
		if *urlEndPoint != "" && *command != "" {
			claims.TokenEndPoint = *urlEndPoint
			claims.AuthorizeEndpoint = *urlEndPoint
			claims.EndSessionEndpoint = ""
		} else {
			log.Fatal(oidcError)
		}
	} else {
		oidcError = provider.Claims(&claims)
		if oidcError != nil {
			log.Fatal(oidcError)
		}
	}
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Renegotiation:      tls.RenegotiateOnceAsClient,
				InsecureSkipVerify: *skipTlsVerification,
			},
		},
	}

	if *clientAssertion != "" {
		if *clientJwtKey != "" || *clientJwtPkcs12 != "" {
			log.Fatal("Invalid state. Provide parameter client_assertion without other private_key_jwt parameters")
		}
		privateKeyJwt = *clientAssertion
	} else if (*clientPkcs12 != "" || *clientJwtPkcs12 != "" || *userPkcs12 != "") && *pin != "" {
		if *clientPkcs12 == "" && *clientJwtPkcs12 != "" {
			clientPkcs12 = clientJwtPkcs12
		} else if *clientPkcs12 == "" && *userPkcs12 != "" && *clientJwtPkcs12 == "" {
			clientPkcs12 = userPkcs12
		}
		p12Data, readError := ioutil.ReadFile(*clientPkcs12)
		if readError != nil {
			log.Println("read pkcs12 failed")
			log.Println(readError)
			return
		}
		blocks, err := pkcs12.ToPEM(p12Data, *pin)
		if err != nil {
			log.Println("decode pkcs12 failed")
			log.Println(err)
			return
		}
		var pemData []byte
		for _, b := range blocks {
			pemData = append(pemData, pem.EncodeToMemory(b)...)
		}

		cert, err := tls.X509KeyPair(pemData, pemData)
		if err != nil {
			log.Println("X509KeyPair failed")
			return
		}

		if *clientJwtPkcs12 != "" {
			cert0, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				log.Fatal(err)
			}
			privateKeyJwt, err = client.CreatePrivateKeyJwt(*clientID, *cert0, claims.TokenEndPoint, cert.PrivateKey)
			if err != nil {
				log.Fatal(err)
			}
			if *command == "jwks" {
				fromRawKey, err := jwk.FromRaw(cert0.PublicKey)
				if err != nil {
					log.Printf("failed to acquire raw key from jwk.Key: %s", err)
					return
				}
				if err != nil {
					log.Printf("failed to acquire raw key from jwk.Key: %s", err)
					return
				}
				sha1Sum := client.CalculateSha1ThumbPrint(*cert0)
				fromRawKey.Set(jwk.KeyIDKey, sha1Sum)
				fromRawKey.Set(jwk.X509CertThumbprintKey, sha1Sum)
				fromRawKey.Set(jwk.AlgorithmKey, "RS256")
				buf, err := json.MarshalIndent(fromRawKey, "", "  ")
				if err != nil {
					fmt.Printf("failed to marshal key into JSON: %s\n", err)
					return
				}
				fmt.Printf("%s\n", buf)
			}
		} else {
			tlsClient = &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						Renegotiation: tls.RenegotiateOnceAsClient,
						Certificates:  []tls.Certificate{cert},
					},
				},
			}
			mTLS = true
		}
	} else if *clientJwtKey != "" {
		if *clientJwtKid == "" {
			log.Fatal("client_jwt_kid is required to run this command")
			return
		}
		kidValue, err := client.CalculateSha1FromX509(*clientJwtKid)
		if err != nil {
			log.Println("read client_jwt_kid value failed")
			log.Println(err)
			return
		}
		pemKey, readError := ioutil.ReadFile(*clientJwtKey)
		if readError != nil {
			log.Println("read private key failed")
			log.Println(readError)
			return
		}
		signKey, err := jwt.ParseRSAPrivateKeyFromPEM(pemKey)
		if err != nil {
			log.Println("decode of RSA private key failed")
			log.Println(err)
			return
		}
		var x5tValue = ""
		if *clientJwtKid != "" {
			x5tValue, err = client.CalculateSha1FromX509(*clientJwtX5t)
			if err != nil {
				log.Println("read x5t value failed")
				log.Println(err)
				return
			}
		}
		privateKeyJwt, err = client.CreatePrivateKeyJwtKid(*clientID, kidValue, x5tValue, claims.TokenEndPoint, signKey)
		if err != nil {
			log.Fatal(err)
			return
		}
	}

	requestMap := url.Values{}
	requestMap.Set("client_id", *clientID)
	if *clientSecret != "" {
		requestMap.Set("client_secret", *clientSecret)
	} else {
		// cf case with an empty secret
		if slices.Contains(arguments, "-client_secret") || slices.Contains(arguments, "--client_secret") {
			requestMap.Set("client_secret", "")
		} else if *doCfCall {
			requestMap.Set("client_secret", *clientSecret)
		}
	}
	if privateKeyJwt != "" {
		requestMap.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		requestMap.Set("client_assertion", privateKeyJwt)
	}
	var verbose = *isVerbose
	if *tokenFormatParameter != "" && *doCfCall == false {
		requestMap.Set("token_format", *tokenFormatParameter)
	}
	if *appTid != "" {
		requestMap.Set("app_tid", *appTid)
	}
	if *refreshExpiry != "" {
		requestMap.Set("refresh_expiry", *refreshExpiry)
	}
	if *loginHint != "" {
		requestMap.Set("login_hint", *loginHint)
	} else if *cfOrigin != "" {
		type loginHint struct {
			Origin string `json:"origin"`
		}
		originStruct := loginHint{*cfOrigin}
		originParam, _ := json.Marshal(originStruct)
		requestMap.Set("login_hint", url.QueryEscape(string(originParam)))
	}
	if *providerName != "" {
		requestMap.Set("resource", "urn:sap:identity:application:provider:name:"+*providerName)
	}
	if *resourceParam != "" {
		requestMap.Add("resource", *resourceParam)
	}

	if *command != "" {
		if *scopeParameter != "" {
			requestMap.Set("scope", *scopeParameter)
		}
		if *refreshExpiry != "" {
			requestMap.Set("refresh_expiry", *refreshExpiry)
		}
		if *command == "client_credentials" {
			client.HandleClientCredential(requestMap, *bearerToken, *provider, *tlsClient, verbose)
		} else if *command == "password" {
			if *userName == "" {
				log.Fatal("username is required to run this command")
			}
			requestMap.Set("username", *userName)
			if *userPassword == "" {
				log.Fatal("password is required to run this command")
			}
			requestMap.Set("password", *userPassword)
			var responseToken = client.HandlePasswordGrant(requestMap, *provider, *tlsClient, verbose)
			if *doCfCall {
				cf.WriteUaaConfig(*issEndPoint, responseToken)
			}
		} else if *command == "token-exchange" {
			requestMap.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
			if *assertionToken == "" {
				if *tokenInput != "" {
					requestMap.Set("subject_token", *tokenInput)
				} else {
					log.Fatal("assertion and/or token parameter not set. Needed to pass it to subject_token for token-exchange")
				}
			} else {
				requestMap.Set("subject_token", *assertionToken)
			}
			if *subjectType == "" {
				log.Fatal("subject_type parameter not set. Supported parameters for token-exchange are, id_token, access_token, refresh_token, jwt")
			} else {
				if strings.Contains(*subjectType, "saml2-session") || strings.Contains(*subjectType, "saml-session") {
					requestMap.Set("subject_token_type", "urn:sap:identity:oauth:token-type:saml2-session")
				} else {
					requestMap.Set("subject_token_type", "urn:ietf:params:oauth:token-type:"+*subjectType)
				}
			}
			if *requestedType == "" {
				log.Fatal("assertion parameter not set. Needed to pass it to subject_token for token-exchange")
			} else {
				if strings.Contains(*requestedType, "saml2-header") || strings.Contains(*requestedType, "saml-header") {
					requestMap.Set("requested_token_type", "urn:sap:identity:oauth:token-type:saml2-header")
				} else {
					requestMap.Set("requested_token_type", "urn:ietf:params:oauth:token-type:"+*requestedType)
				}
			}
			var exchangedTokenResponse = client.HandleTokenExchangeGrant(requestMap, claims.TokenEndPoint, *tlsClient, verbose)
			if *doCfCall {
				fmt.Println(exchangedTokenResponse.AccessToken)
				cf.WriteUaaConfig(*issEndPoint, exchangedTokenResponse)
			} else {
				if exchangedTokenResponse.IdToken != "" {
					fmt.Println(exchangedTokenResponse.IdToken)
				} else {
					fmt.Println(exchangedTokenResponse.AccessToken)
				}
			}
		} else if *command == "jwt-bearer" {
			requestMap.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
			if *assertionToken == "" {
				log.Fatal("assertion parameter not set. Needed to pass it for JWT bearer")
			}
			requestMap.Set("assertion", *assertionToken)
			var jwtBearerTokenResponse = client.HandleJwtBearerGrant(requestMap, claims.TokenEndPoint, *tlsClient, verbose)
			if *doCfCall {
				fmt.Println(jwtBearerTokenResponse.AccessToken)
				cf.WriteUaaConfig(*issEndPoint, jwtBearerTokenResponse)
			} else if jwtBearerTokenResponse.IdToken != "" {
				fmt.Println(jwtBearerTokenResponse.IdToken)
			} else {
				fmt.Println(jwtBearerTokenResponse.AccessToken)
			}
		} else if *command == "saml-bearer" {
			requestMap.Set("grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer")
			if *assertionToken == "" {
				log.Fatal("assertion parameter not set. Needed to pass it for SAML bearer")
			}
			requestMap.Set("assertion", *assertionToken)
			var samlBearerTokenResponse = client.HandleSamlBearerGrant(requestMap, claims.TokenEndPoint, *tlsClient, verbose)
			fmt.Println(samlBearerTokenResponse.AccessToken)
			if *doCfCall {
				cf.WriteUaaConfig(*issEndPoint, samlBearerTokenResponse)
			}
		} else if *command == "passcode" {
			if *issEndPoint == "" || !strings.HasPrefix(*issEndPoint, "https://") {
				log.Fatal("issuer with https schema is required to run this command")
			}
			if *userPkcs12 == "" {
				log.Fatal("user_tls parameter is required in order to execute passcode")
			}
			var passcode = client.HandlePasscode(*issEndPoint, *tlsClient, verbose)
			fmt.Println(passcode)
		} else if *command == "idp_token" {
			if *assertionToken == "" {
				log.Println("No id_token token received.")
				return
			}
			if *clientSecret == "" && mTLS == false && privateKeyJwt == "" && *bearerToken == "" {
				log.Fatal("client_secret is required to run this command")
				return
			}
			var idpTokenResponse = client.HandleCorpIdpExchangeFlow(*clientID, *clientSecret, *bearerToken, *assertionToken, *idpScopeParameter, privateKeyJwt, claims.TokenEndPoint, *tlsClient)
			data, _ := json.MarshalIndent(idpTokenResponse, "", "    ")
			if verbose {
				fmt.Println("Response from endpoint /exchange/corporateidp")
			}
			fmt.Println(string(data))
		} else if *command == "introspect" {
			if *tokenInput == "" {
				log.Fatal("token parameter not set. Needed to pass it for validation")
			}
			if *clientID != "" && *clientID != "T000000" {
				requestMap.Set("client_id", *clientID)
			} else {
				requestMap.Del("client_id")
			}
			client.HandleTokenIntrospect(requestMap, *tokenInput, claims.IntroSpectEndpoint, *tlsClient, verbose)
		} else if *command == "jwks" {
		}
	} else {
		// nonceParameter, only in authorize
		if *nonceParameter != "" {
			requestMap.Set("nonce", *nonceParameter)
		}
		if *promptParameter != "" {
			requestMap.Set("prompt", *promptParameter)
		}
		if *maxAgeParameter != "" {
			requestMap.Set("max_age", *maxAgeParameter)
		}
		var idToken, refreshToken = client.HandleOpenIDFlow(requestMap, verbose, callbackURL, *scopeParameter, *tokenFormatParameter, *portParameter, claims.EndSessionEndpoint, privateKeyJwt, *provider, *tlsClient)
		if *doRefresh {
			if refreshToken == "" {
				log.Println("No refresh token received.")
				return
			}
			var newRefresh = client.HandleRefreshFlow(*clientID, *appTid, *clientSecret, refreshToken, *refreshExpiry, privateKeyJwt, *skipTlsVerification, *provider)
			if verbose {
				log.Println("Old refresh token: " + refreshToken)
				log.Println("New refresh token: " + newRefresh)
			}
		}
		if *doCorpIdpTokenExchange {
			if idToken == "" {
				log.Println("No id_token token received.")
				return
			}
			if *clientSecret == "" && mTLS == false && privateKeyJwt == "" && *bearerToken == "" {
				log.Fatal("client_secret is required to run this command")
				return
			}
			var idpTokenResponse = client.HandleCorpIdpExchangeFlow(*clientID, *clientSecret, *bearerToken, idToken, *idpScopeParameter, privateKeyJwt, claims.TokenEndPoint, *tlsClient)
			data, _ := json.MarshalIndent(idpTokenResponse, "", "    ")
			if verbose {
				fmt.Println("Response from endpoint /exchange/corporateidp")
			}
			fmt.Println(string(data))
		}
		if *requestedType != "" && idToken != "" {
			requestMap.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
			requestMap.Set("subject_token_type", "urn:ietf:params:oauth:token-type:id_token")
			requestMap.Set("subject_token", idToken)
			if strings.Contains(*requestedType, "saml2-header") || strings.Contains(*requestedType, "saml-header") {
				requestMap.Set("requested_token_type", "urn:sap:identity:oauth:token-type:saml2-header")
			} else {
				requestMap.Set("requested_token_type", "urn:ietf:params:oauth:token-type:"+*requestedType)
			}
			if *providerName != "" {
				requestMap.Set("resource", "urn:sap:identity:application:provider:name:"+*providerName)
			}
			if *resourceParam != "" {
				requestMap.Add("resource", *resourceParam)
			}

			var exchangedTokenResponse = client.HandleTokenExchangeGrant(requestMap, claims.TokenEndPoint, *tlsClient, verbose)
			fmt.Println(exchangedTokenResponse)
		}
		if *doIntrospect && idToken != "" && claims.IntroSpectEndpoint != "" {
			requestMap := url.Values{}
			requestMap.Set("client_id", *clientID)
			client.HandleTokenIntrospect(requestMap, idToken, claims.IntroSpectEndpoint, *tlsClient, verbose)
		}
	}
}

func showVersion() {
	if date != "" && date != "unknown" {
		fmt.Println("openid-client version:", version, "commit:", commit, "built at:", date)
	} else {
		fmt.Println("openid-client version:", version, "commit:", commit)
	}
}
