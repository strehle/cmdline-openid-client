package client

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

var (
	agent = "OpenId Client/GO/1"
)

func HandleCorpIdpExchangeFlow(clientID string, clientSecret string, bearerToken string, existingIdToken string, idpScopeParameter string, privateKeyJwt string, tokenEndpoint string, tlsClient http.Client) map[string]interface{} {

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

	tokenEndPoint := strings.Replace(tokenEndpoint, "/token", "/exchange/corporateidp", 1)
	fmt.Println("Call IdP Token Exchange Endpoint: " + tokenEndPoint)
	req, err := http.NewRequest("POST", tokenEndPoint, body)
	if err != nil {
		log.Fatal("Error from token exchange: " + err.Error())
	}
	if clientSecret != "" {
		req.SetBasicAuth(clientID, clientSecret)
	} else if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", agent)
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

func HandleTokenExchangeGrant(request url.Values, tokenEndpoint string, tlsClient http.Client, verbose bool) OpenIdToken {
	var oidctoken OpenIdToken
	request.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	req, requestError := http.NewRequest("POST", tokenEndpoint, strings.NewReader(request.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", agent)
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
		var myToken OpenIdToken
		json.Unmarshal([]byte(jsonStr), &myToken)
		if myToken.AccessToken == "" {
			fmt.Println(string(jsonStr))
		} else {
			if verbose {
				fmt.Println("Response from token-exchange endpoint ")
				ShowJSonResponse(result, verbose)
			}
			oidctoken = myToken
		}
	}
	return oidctoken
}

func HandleJwtBearerGrant(request url.Values, tokenEndpoint string, tlsClient http.Client, verbose bool) OpenIdToken {
	var oidctoken OpenIdToken
	request.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	req, requestError := http.NewRequest("POST", tokenEndpoint, strings.NewReader(request.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", agent)
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
		var myToken OpenIdToken
		json.Unmarshal([]byte(jsonStr), &myToken)
		if myToken.AccessToken == "" {
			fmt.Println(string(jsonStr))
		} else {
			if verbose {
				fmt.Println("Response from JWT bearer endpoint ")
				ShowJSonResponse(result, verbose)
			}
			oidctoken = myToken
		}
	}
	return oidctoken
}

func HandleSamlBearerGrant(request url.Values, tokenEndpoint string, tlsClient http.Client, verbose bool) OpenIdToken {
	var oidctoken OpenIdToken
	request.Set("grant_type", "urn:ietf:params:oauth:grant-type:saml2-bearer")
	req, requestError := http.NewRequest("POST", tokenEndpoint, strings.NewReader(request.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", agent)
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
		var myToken OpenIdToken
		json.Unmarshal([]byte(jsonStr), &myToken)
		if myToken.AccessToken == "" {
			fmt.Println(string(jsonStr))
		} else {
			if verbose {
				fmt.Println("Response from SAML bearer endpoint ")
				ShowJSonResponse(result, verbose)
			}
			oidctoken = myToken
		}
	}
	return oidctoken
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
	req.Header.Set("User-Agent", agent)
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

func HandleTokenIntrospect(request url.Values, token string, tokenEndpoint string, tlsClient http.Client, verbose bool) string {
	request.Set("token", token)
	req, requestError := http.NewRequest("POST", tokenEndpoint, strings.NewReader(request.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", agent)
	resp, clientError := tlsClient.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	var result map[string]interface{}
	var resultString string
	json.NewDecoder(resp.Body).Decode(&result)
	if result != nil {
		jsonStr, marshalError := json.MarshalIndent(result, "", "    ")
		if marshalError != nil {
			log.Fatal(marshalError)
		}
		resultString = string(jsonStr)
		if verbose {
			fmt.Println("Response from token introspect endpoint ")
			ShowJSonResponse(result, verbose)
		} else {
			fmt.Println(resultString)
		}
	}
	return resultString
}
