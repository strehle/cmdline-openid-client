package main

import (
	"flag"
	"fmt"
	"log"

	oidc "github.com/coreos/go-oidc"
	"github.com/strehle/cmdline-openid-client/pkg/client"
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
			"      -scope            OIDC scope parameter. This is an optional flag, default is openid. If you set none the parameter scope will be omitted in request.\n" +
			"      -refresh          Bool flag. Default false. If true, call refresh flow for the received id_token.\n" +
			"      -idp_token        Bool flag. Default false. If true, call the OIDC IdP token exchange endpoint (IAS specific only) and return the response.\n" +
			"      -refresh_expiry   Value in seconds. Optional parameter to reduce Refresh Token Lifetime.\n" +
			"      -token_format     Format for access_token. Possible values are opaque and jwt. Optional parameter, default: opaque\n" +
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

	var callbackURL = "http://localhost:" + *portParameter + "/callback"

	flag.Parse()
	if *clientID == "" {
		log.Fatal("client_id is required to run this command")
	} else if *issEndPoint == "" {
		log.Fatal("issuer is required to run this command")
	}
	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, *issEndPoint)
	if err != nil {
		log.Fatal(err)
	}
	var accessToken, refreshToken = client.HandleOpenIDFlow(*clientID, *clientSecret, callbackURL, *scopeParameter, *refreshExpiry, *tokenFormatParameter, *portParameter, *provider)
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
		if accessToken == "" {
			log.Println("No access token received.")
			return
		}
		if *clientSecret == "" {
			log.Fatal("client_secret is required to run this command")
			return
		}
		var idpTokenResponse = client.HandleCorpIdpExchangeFlow(*clientID, *clientSecret, accessToken, *provider)
		log.Println("IDP token response")
		log.Println(idpTokenResponse)
	}
}
