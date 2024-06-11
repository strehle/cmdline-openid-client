package client

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

func HandleCorpIdpExchangeFlow(clientID string, clientSecret string, existingIdToken string, idpScopeParameter string, privateKeyJwt string, provider oidc.Provider, tlsClient http.Client) map[string]interface{} {

	params := url.Values{}
	params.Add("assertion", existingIdToken)
	params.Add("response_type", `token id_token`)
	params.Add("client_id", clientID)
	if privateKeyJwt != "" {
		params.Add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		params.Add("client_assertion", privateKeyJwt)
	}
	if idpScopeParameter != "" {
		params.Add("scope", idpScopeParameter)
	}

	body := strings.NewReader(params.Encode())

	tokenEndPoint := strings.Replace(provider.Endpoint().TokenURL, "/token", "/exchange/corporateidp", 1)
	fmt.Println("Call IdP Token Exchange Endpoint: " + tokenEndPoint)
	req, err := http.NewRequest("POST", tokenEndPoint, body)
	if err != nil {
		log.Fatal("Error from token exchange: " + err.Error())
	}
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := tlsClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var outBodyMap map[string]interface{}
	if resp.StatusCode == http.StatusOK {
		json.Unmarshal(bodyBytes, &outBodyMap)
	} else {
		log.Fatal("Error from token exchange: " + string(bodyBytes))
		log.Fatal(string(bodyBytes))
	}
	return outBodyMap
}
