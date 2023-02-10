package main

import (
	"crypto/tls"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"github.com/strehle/cmdline-openid-client/pkg/client"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/net/context"
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
			"      -client_tls       OIDC client mTLS authentication. This is an optional flag and only needed for confidential clients as replacement for client_secret.\n" +
			"      -scope            OIDC scope parameter. This is an optional flag, default is openid. If you set none, the parameter scope will be omitted in request.\n" +
			"      -refresh          Bool flag. Default false. If true, call refresh flow for the received id_token.\n" +
			"      -idp_token        Bool flag. Default false. If true, call the OIDC IdP token exchange endpoint (IAS specific only) and return the response.\n" +
			"      -idp_scope        OIDC scope parameter. Default no scope is set. If you set the parameter idp_scope, it is set in IdP token exchange endpoint (IAS specific only).\n" +
			"      -refresh_expiry   Value in seconds. Optional parameter to reduce Refresh Token Lifetime.\n" +
			"      -token_format     Format for access_token. Possible values are opaque and jwt. Optional parameter, default: opaque\n" +
			"      -pin              PIN to PKCS12 file\n" +
			"      -port             Callback port. Open on localhost a port to retrieve the authorization code. Optional parameter, default: 8080\n" +
			"      -h                Show this help\n")
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
	var pin = flag.String("pin", "", "PIN to PKCS12 file")
	var mTLS bool = false
	flag.Parse()
	if *clientID == "" {
		log.Fatal("client_id is required to run this command")
	} else if *issEndPoint == "" {
		log.Fatal("issuer is required to run this command")
	}
	var callbackURL = "http://localhost:" + *portParameter + "/callback"
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, *issEndPoint)
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
	if *clientPkcs12 != "" && *pin != "" {
		p12_data, err := ioutil.ReadFile(*clientPkcs12)
		if err != nil {
			log.Println("read pkcs12 failed")
			log.Println(err)
			return
		}
		blocks, err := pkcs12.ToPEM(p12_data, *pin)
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

		tlsClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					Certificates: []tls.Certificate{cert},
				},
			},
		}
		mTLS = true
	}

	var idToken, refreshToken = client.HandleOpenIDFlow(*clientID, *clientSecret, callbackURL, *scopeParameter, *refreshExpiry, *tokenFormatParameter, *portParameter, *provider, *tlsClient)
	if *doRefresh {
		if refreshToken == "" {
			log.Println("No refresh token received.")
			return
		}
		var newRefresh = client.HandleRefreshFlow(*clientID, *clientSecret, refreshToken, *refreshExpiry, *provider)
		log.Println("Old refresh token: " + refreshToken)
		log.Println("New refresh token: " + newRefresh)
	}
	if *doCorpIdpTokenExchange {
		if idToken == "" {
			log.Println("No id_token token received.")
			return
		}
		if *clientSecret == "" && mTLS == false {
			log.Fatal("client_secret is required to run this command")
			return
		}
		var idpTokenResponse = client.HandleCorpIdpExchangeFlow(*clientID, *clientSecret, idToken, *idpScopeParameter, *provider, *tlsClient)
		log.Println("IDP token response")
		log.Println(idpTokenResponse)
	}
}
