package client

import (
	"bytes"
	"encoding/base64"
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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

func HandleTokenRevocation(request url.Values, token string, tokenEndpoint string, tlsClient http.Client, verbose bool) string {
	request.Set("token", token)
	req, requestError := http.NewRequest("POST", strings.Replace(tokenEndpoint, "/oauth2/token", "/oauth2/revoke", 1), strings.NewReader(request.Encode()))
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
	defer resp.Body.Close()
	var result map[string]interface{}
	var resultString string
	json.NewDecoder(resp.Body).Decode(&result)
	if resp.StatusCode != 200 {
		jsonStr, marshalError := json.MarshalIndent(result, "", "    ")
		if marshalError != nil {
			log.Fatal(marshalError)
		}
		resultString = string(jsonStr)
		if verbose {
			fmt.Println("Response from token revocation endpoint ")
		}
		ShowJSonResponse(result, verbose)
	} else {
		resultString = "Token revoked successfully"
		fmt.Println(resultString)
	}
	return resultString
}

func HandleUserInfo(token string, tokenEndpoint string, tlsClient http.Client, verbose bool) string {
	req, requestError := http.NewRequest("GET", tokenEndpoint, nil)
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("User-Agent", agent)
	resp, clientError := tlsClient.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	defer resp.Body.Close()
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
			fmt.Println("Response from userinfo endpoint ")
			ShowJSonResponse(result, verbose)
		} else {
			fmt.Println(resultString)
		}
	}
	return resultString
}

func HandleDecodeJwt(token string, headerOnly bool, payloadOnly bool, raw bool) {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 3 {
		log.Fatalf("unsupported token format: decode only supports signed JWTs (JWS compact serialization, 3 parts); got %d parts", len(parts))
	}
	header, err := decodeJwtPart(parts[0])
	if err != nil {
		log.Fatalf("failed to decode JWT header: %v", err)
	}
	payload, err := decodeJwtPart(parts[1])
	if err != nil {
		log.Fatalf("failed to decode JWT payload: %v", err)
	}

	switch {
	case headerOnly:
		printJwt(header, raw)
	case payloadOnly:
		printJwt(payload, raw)
	default:
		fmt.Println("Header:")
		printColorJSON(header)
		fmt.Println("\nPayload:")
		printColorJSON(payload)
	}
}

func printJwt(v map[string]interface{}, raw bool) {
	if raw {
		data, err := json.MarshalIndent(v, "", "    ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(data))
	} else {
		printColorJSON(v)
	}
}

func decodeJwtPart(part string) (map[string]interface{}, error) {
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return nil, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// ANSI color codes matching jq's default palette
const (
	colorReset  = "\033[0m"
	colorKey    = "\033[34;1m" // bold blue  — object keys
	colorString = "\033[0;32m" // green       — string values
	colorNumber = "\033[0;39m" // default fg  — numbers (jq uses no color)
	colorBool   = "\033[0;39m" // default fg  — true/false/null
)

func printColorJSON(v map[string]interface{}) {
	raw, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(colorizeJSON(string(raw)))
}

// colorizeJSON applies jq-style ANSI coloring to indented JSON text.
func colorizeJSON(src string) string {
	var buf bytes.Buffer

	// Post-process the pre-indented string line by line.
	lines := strings.Split(src, "\n")
	for _, line := range lines {
		buf.WriteString(colorizeLine(line))
		buf.WriteByte('\n')
	}
	// trim trailing newline added above to match the original
	result := buf.String()
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}
	return result
}

// colorizeLine colorizes a single line of indented JSON.
func colorizeLine(line string) string {
	trimmed := strings.TrimLeft(line, " \t")
	indent := line[:len(line)-len(trimmed)]

	// Object key: starts with a quoted string followed by a colon
	if strings.HasPrefix(trimmed, `"`) {
		colonIdx := indexAfterString(trimmed)
		if colonIdx >= 0 && colonIdx < len(trimmed) && trimmed[colonIdx] == ':' {
			key := trimmed[:colonIdx]
			rest := trimmed[colonIdx:] // ": <value>"
			coloredKey := colorKey + key + colorReset
			coloredRest := colorizeValue(rest[1:]) // strip leading ':'
			return indent + coloredKey + ":" + coloredRest
		}
	}
	// Standalone value (array element or bare value line).
	// colorizeValue prefixes a space (intended for after the ':' in key-value
	// pairs), so strip it here to preserve the original indentation.
	return indent + strings.TrimPrefix(colorizeValue(trimmed), " ")
}

// colorizeValue colors the value portion of a JSON line (may have trailing comma).
func colorizeValue(s string) string {
	s = strings.TrimLeft(s, " ")
	if len(s) == 0 {
		return s
	}

	// Detect trailing comma
	trail := ""
	core := s
	if strings.HasSuffix(s, ",") {
		trail = ","
		core = s[:len(s)-1]
	}
	core = strings.TrimRight(core, " ")

	switch {
	case core == "{" || core == "}" || core == "[" || core == "]" ||
		core == "{}" || core == "[]":
		return " " + core + trail
	case strings.HasPrefix(core, `"`):
		return " " + colorString + core + colorReset + trail
	case core == "true" || core == "false" || core == "null":
		return " " + colorBool + core + colorReset + trail
	default:
		// number or unrecognized
		return " " + colorNumber + core + colorReset + trail
	}
}

// indexAfterString returns the index of the character immediately after the
// closing quote of the first JSON string in s, or -1 if s doesn't start with
// a valid quoted string.
func indexAfterString(s string) int {
	if len(s) == 0 || s[0] != '"' {
		return -1
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '\\' {
			i++ // skip escaped character
			continue
		}
		if s[i] == '"' {
			return i + 1
		}
	}
	return -1
}

// HandleClientRegistration performs RFC 7591 Dynamic Client Registration.
// registrationEndpoint is the server's registration endpoint.
// metadata is a map of client metadata fields (redirect_uris, grant_types, etc.).
// bearerToken is the optional initial access token for protected endpoints.
func HandleClientRegistration(metadata map[string]interface{}, bearerToken string, clientID string, clientSecret string, registrationEndpoint string, tlsClient http.Client, verbose bool) map[string]interface{} {
	body, err := json.Marshal(metadata)
	if err != nil {
		log.Fatal("Error marshaling registration request: " + err.Error())
	}
	req, requestError := http.NewRequest("POST", registrationEndpoint, bytes.NewReader(body))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", agent)
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	} else if clientID != "" && clientSecret != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	if verbose {
		fmt.Println("POST " + registrationEndpoint)
		fmt.Println(string(body))
	}
	resp, clientError := tlsClient.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}
	var result map[string]interface{}
	json.Unmarshal(bodyBytes, &result)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		log.Fatal("Registration failed (" + resp.Status + "): " + string(bodyBytes))
	}
	data, _ := json.MarshalIndent(result, "", "    ")
	fmt.Println(string(data))
	return result
}

func HandleTokenList(request url.Values, token string, tokenEndpoint string, tlsClient http.Client, verbose bool) string {
	request.Set("token", token)
	req, requestError := http.NewRequest("POST", tokenEndpoint+"/list", strings.NewReader(request.Encode()))
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
	defer resp.Body.Close()
	var result []interface{}
	var resultString string
	json.NewDecoder(resp.Body).Decode(&result)
	if result != nil {
		jsonStr, marshalError := json.MarshalIndent(result, "", "    ")
		if marshalError != nil {
			log.Fatal(marshalError)
		}
		resultString = string(jsonStr)
		if verbose {
			fmt.Println("Response from token list endpoint ")
			fmt.Println("==========")
			fmt.Println(resultString)
			fmt.Println("==========")
		} else {
			fmt.Println(resultString)
		}
	}
	return resultString
}
