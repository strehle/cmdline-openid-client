package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	oidc "github.com/coreos/go-oidc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/strehle/cmdline-openid-client/pkg/client"
	"golang.org/x/net/context"
	"software.sslmate.com/src/go-pkcs12"
)

func main() {
	flag.Usage = func() {
		fmt.Println("Usage: openid-client \n" +
			"       This is a CLI to generate tokens from an OpenID Connect (OIDC) complaiant server. Create a service provider/application in the OIDC server with call back url:\n" +
			"       http://localhost:<port>/callback and set below flags to get an ID token\n" +
			"Flags:\n" +
			"      -issuer           IAS. Default is https://<yourtenant>.accounts.ondemand.com; XSUAA Default is: https://uaa.cf.eu10.hana.ondemand.com/oauth/token\n" +
			"      -client_id        OIDC client ID. This is a mandatory flag.\n" +
			"      -client_secret    OIDC client secret. This is an optional flag and only needed for confidential clients.\n" +
			"      -client_tls       P12 file for client mTLS authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.\n" +
			"      -client_jwt       P12 file for private_key_jwt authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.\n" +
			"      -client_jwt_key   Private Key in PEM for private_key_jwt authentication. Use this parameter together with -client_jwt_kid. Replaces -client_jwt and -pin.\n" +
			"      -client_jwt_kid   Key ID for private_key_jwt authentication. Use this parameter together with -client_jwt_key. Replaces -client_jwt and -pin.\n" +
			"      -scope            OIDC scope parameter. This is an optional flag, default is openid. If you set none, the parameter scope will be omitted in request.\n" +
			"      -refresh          Bool flag. Default false. If true, call refresh flow for the received id_token.\n" +
			"      -idp_token        Bool flag. Default false. If true, call the OIDC IdP token exchange endpoint (IAS specific only) and return the response.\n" +
			"      -idp_scope        OIDC scope parameter. Default no scope is set. If you set the parameter idp_scope, it is set in IdP token exchange endpoint (IAS specific only).\n" +
			"      -refresh_expiry   Value in seconds. Optional parameter to reduce Refresh Token Lifetime.\n" +
			"      -token_format     Format for access_token. Possible values are opaque and jwt. Optional parameter, default: opaque\n" +
			"      -cmd              Single command to be executed. Supported commands currently: jwks, client_credentials\n" +
			"      -pin              PIN to P12/PKCS12 file using -client_tls or -client_jwt \n" +
			"      -port             Callback port. Open on localhost a port to retrieve the authorization code. Optional parameter, default: 8080\n" +
			"      -h                Show this help")
	}

	var issEndPoint = flag.String("issuer", "", "OIDC Issuer URI")
	var clientID = flag.String("client_id", "", "OIDC client ID")
	var clientSecret = flag.String("client_secret", "", "OIDC client secret")
	var doRefresh = flag.Bool("refresh", false, "Refresh the received id_token")
	var scopeParameter = flag.String("scope", "", "OIDC scope parameter")
	var doCorpIdpTokenExchange = flag.Bool("idp_token", false, "Return OIDC IdP token response")
	var refreshExpiry = flag.String("refresh_expiry", "", "Value in secondes to reduce Refresh Token Lifetime")
	var tokenFormatParameter = flag.String("token_format", "opaque", "Format for access_token")
	var portParameter = flag.String("port", "8080", "Callback port on localhost")
	var idpScopeParameter = flag.String("idp_scope", "", "Request scope parameter in OIDC IdP token")
	var clientPkcs12 = flag.String("client_tls", "", "PKCS12 file for OIDC client mTLS authentication")
	var clientJwtPkcs12 = flag.String("client_jwt", "", "PKCS12 file for OIDC private_key_jwt authentication")
	var pin = flag.String("pin", "", "PIN to PKCS12 file")
	var clientJwtKey = flag.String("client_jwt_key", "", "Private Key signing the client JWT for private_key_jwt authentication")
	var clientJwtKid = flag.String("client_jwt_kid", "", "Key ID of client JWT for private_key_jwt authentication")
	var command = flag.String("cmd", "", "Single command to be executed")
	var mTLS bool = false
	var privateKeyJwt string = ""
	flag.Parse()
	if *command == "jwks" {
		*issEndPoint = "https://accounts.sap.com"
	} else {
		if *clientID == "" {
			log.Fatal("client_id is required to run this command")
		} else if *issEndPoint == "" {
			log.Fatal("issuer is required to run this command")
		}
	}
	var callbackURL = "http://localhost:" + *portParameter + "/callback"
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, *issEndPoint)
	if err != nil {
		log.Fatal(err)
	}
	var claims struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
		TokenEndPoint      string `json:"token_endpoint"`
	}
	err = provider.Claims(&claims)
	if err != nil {
		log.Fatal(err)
	}
	tlsClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	if (*clientPkcs12 != "" || *clientJwtPkcs12 != "") && *pin != "" {
		if *clientPkcs12 == "" {
			clientPkcs12 = clientJwtPkcs12
		}
		p12Data, readerror := ioutil.ReadFile(*clientPkcs12)
		if readerror != nil {
			log.Println("read pkcs12 failed")
			log.Println(readerror)
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
						Certificates: []tls.Certificate{cert},
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
		pemKey, readerror := ioutil.ReadFile(*clientJwtKey)
		if readerror != nil {
			log.Println("read private key failed")
			log.Println(readerror)
			return
		}
		signKey, err := jwt.ParseRSAPrivateKeyFromPEM(pemKey)
		if err != nil {
			log.Println("decode of RSA private key failed")
			log.Println(err)
			return
		}
		privateKeyJwt, err = client.CreatePrivateKeyJwtKid(*clientID, *clientJwtKid, claims.TokenEndPoint, signKey)
		if err != nil {
			log.Fatal(err)
			return
		}
	}

	requestMap := url.Values{}
	requestMap.Set("client_id", *clientID)
	if *clientSecret != "" {
		requestMap.Set("client_secret", *clientSecret)
	}
	if privateKeyJwt != "" {
		requestMap.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		requestMap.Set("client_assertion", privateKeyJwt)
	}
	var verbose = true
	if *tokenFormatParameter != "" {
		requestMap.Set("token_format", *tokenFormatParameter)
		verbose = false
	}
	if *refreshExpiry != "" {
		requestMap.Set("refresh_expiry", *refreshExpiry)
	}

	if *command != "" {
		if *command == "client_credentials" {
			client.HandleClientCredential(requestMap, *provider, *tlsClient, verbose)
		} else if *command == "jwks" {
		}
	} else {
		var idToken, refreshToken = client.HandleOpenIDFlow(*clientID, *clientSecret, callbackURL, *scopeParameter, *refreshExpiry, *tokenFormatParameter, *portParameter, claims.EndSessionEndpoint, privateKeyJwt, *provider, *tlsClient)
		if *doRefresh {
			if refreshToken == "" {
				log.Println("No refresh token received.")
				return
			}
			var newRefresh = client.HandleRefreshFlow(*clientID, *clientSecret, refreshToken, *refreshExpiry, privateKeyJwt, *provider)
			log.Println("Old refresh token: " + refreshToken)
			log.Println("New refresh token: " + newRefresh)
		}
		if *doCorpIdpTokenExchange {
			if idToken == "" {
				log.Println("No id_token token received.")
				return
			}
			if *clientSecret == "" && mTLS == false && privateKeyJwt == "" {
				log.Fatal("client_secret is required to run this command")
				return
			}
			var idpTokenResponse = client.HandleCorpIdpExchangeFlow(*clientID, *clientSecret, idToken, *idpScopeParameter, privateKeyJwt, *provider, *tlsClient)
			data, _ := json.MarshalIndent(idpTokenResponse, "", "    ")
			fmt.Println("Response from endpoint /exchange/corporateidp")
			fmt.Println(string(data))
		}
	}
}
