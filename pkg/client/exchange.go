package client

import (
	"encoding/json"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
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

func HandleTokenExchangeGrant(request url.Values, provider oidc.Provider, tlsClient http.Client, verbose bool) string {
	accessToken := ""
	request.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	req, requestError := http.NewRequest("POST", provider.Endpoint().TokenURL, strings.NewReader(request.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, clientError := tlsClient.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result != nil {
		jsonStr, marshalError := json.Marshal(result)
		if marshalError != nil {
			log.Fatal(marshalError)
		}
		var myToken oauth2.Token
		json.Unmarshal([]byte(jsonStr), &myToken)
		if myToken.AccessToken == "" {
			fmt.Println(string(jsonStr))
		} else {
			if verbose {
				fmt.Println("Response from token-exchange endpoint ")
				ShowJSonResponse(result, verbose)
			}
			accessToken = myToken.AccessToken
		}
	}
	return accessToken
}

func HandleJwtBearerGrant(request url.Values, provider oidc.Provider, tlsClient http.Client, verbose bool) string {
	accessToken := ""
	request.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	req, requestError := http.NewRequest("POST", provider.Endpoint().TokenURL, strings.NewReader(request.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, clientError := tlsClient.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result != nil {
		jsonStr, marshalError := json.Marshal(result)
		if marshalError != nil {
			log.Fatal(marshalError)
		}
		var myToken oauth2.Token
		json.Unmarshal([]byte(jsonStr), &myToken)
		if myToken.AccessToken == "" {
			fmt.Println(string(jsonStr))
		} else {
			if verbose {
				fmt.Println("Response from JWT bearer endpoint ")
				ShowJSonResponse(result, verbose)
			}
			accessToken = myToken.AccessToken
		}
	}
	return accessToken
}

func ShowJSonResponse(result map[string]interface{}, verbose bool) {
	fmt.Println("==========")
	resultJson, _ := json.MarshalIndent(result, "", "    ")
	if verbose {
		fmt.Println("OIDC Response Body")
	}
	fmt.Println(string(resultJson))
	fmt.Println("==========")
}

func HandlePasscode(issuer string, tlsClient http.Client, verbose bool) string {
	passcode := ""
	passcodeUrl := issuer + "/service/users/passcode"
	req, requestError := http.NewRequest("GET", passcodeUrl, nil)
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Accept", "application/json")
	resp, clientError := tlsClient.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result != nil {
		if val, ok := result["passcode"]; ok {
			passcode = val.(string)
			if verbose {
				fmt.Println("Response from Passcode endpoint ")
				ShowJSonResponse(result, verbose)
			}
		} else {
			jsonStr, marshalError := json.Marshal(result)
			if marshalError != nil {
				log.Fatal(marshalError)
			}
			fmt.Println(string(jsonStr))
		}
	}
	return passcode
}
