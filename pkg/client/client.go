package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/akshaybabloo/pkce"
	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

type callbackEndpoint struct {
	server         *http.Server
	code           string
	shutdownSignal chan string
}

func (h *callbackEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	code := r.URL.Query().Get("code")
	if code != "" {
		h.code = code
		fmt.Fprintln(w, "Login is successful, You may close the browser and goto commandline")
	} else {
		fmt.Fprintln(w, "Login is not successful, You may close the browser and try again")
	}
	h.shutdownSignal <- "shutdown"
}

func HandleOpenIDFlow(clientID, clientSecret, callbackURL string, scopeParameter string, refreshExpiry string, provider oidc.Provider) (string, string) {

	refreshToken := ""
	accessToken := ""
	authrizationScope := "openid"
	callbackEndpoint := &callbackEndpoint{}
	callbackEndpoint.shutdownSignal = make(chan string)
	server := &http.Server{
		Addr:           ":7000",
		Handler:        nil,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	callbackEndpoint.server = server
	http.Handle("/callback", callbackEndpoint)
	authzURL, authzURLParseError := url.Parse(provider.Endpoint().AuthURL)

	if authzURLParseError != nil {
		log.Fatal(authzURLParseError)
	}
	p := pkce.Pkce{
		Length: 128,
	}
	codeChallenge, err := p.ChallengeCode()
	if err != nil {
		log.Fatal(err)
	}
	codeVerifier, err := p.VerifyCode()
	if err != nil {
		log.Fatal(err)
	}
	query := authzURL.Query()
	query.Set("response_type", "code")
	if scopeParameter != "" {
		if scopeParameter != "none" {
			query.Set("scope", scopeParameter)
		}
	} else {
		query.Set("scope", authrizationScope)
	}
	query.Set("client_id", clientID)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	query.Set("redirect_uri", callbackURL)
	authzURL.RawQuery = query.Encode()

	//cmd := exec.Command("open", authzURL.String())
	fmt.Println("Execute URL: ", authzURL.String())

	cmd := exec.Command("", authzURL.String())
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", authzURL.String())
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", authzURL.String())
	case "darwin":
		cmd = exec.Command("open", authzURL.String())
	default:
		cmd = nil
		fmt.Printf("unsupported platform")
		return "", ""

	}
	cmdErorr := cmd.Start()
	if cmdErorr != nil {
		log.Fatal(authzURLParseError)
	}

	go func() {
		server.ListenAndServe()
	}()

	<-callbackEndpoint.shutdownSignal
	callbackEndpoint.server.Shutdown(context.Background())
	log.Println("Authorization code is ", callbackEndpoint.code)
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	vals := url.Values{}
	vals.Set("grant_type", "authorization_code")
	vals.Set("code", callbackEndpoint.code)
	vals.Set("redirect_uri", callbackURL)
	vals.Set("code_verifier", codeVerifier)
	//vals.Set("code_verifier", "01234567890123456789012345678901234567890123456789")
	vals.Set("client_id", clientID)
	if clientSecret != "" {
		vals.Set("client_secret", clientSecret)
	}
	if refreshExpiry != "" {
		vals.Set("refresh_expiry", refreshExpiry)
	}
	req, requestError := http.NewRequest("POST", provider.Endpoint().TokenURL, strings.NewReader(vals.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, clientError := client.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println("==========")
	fmt.Println("OIDC Response Body: ", string(result))
	fmt.Println("==========")

	if resp.StatusCode == 200 && result != nil {
		var jsonStr = result
		ctx := context.Background()
		var myToken oauth2.Token
		json.Unmarshal([]byte(jsonStr), &myToken)
		fmt.Println("ID Token ", myToken.AccessToken)
		if myToken.AccessToken == "" {
			fmt.Println(string(jsonStr))
		} else {
			// access_token
			accessToken = myToken.AccessToken
			// refresh token
			refreshToken = myToken.RefreshToken
			// Getting now the userInfo
			fmt.Println("Call now UserInfo ")
			userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&myToken))
			if err != nil {
				log.Fatal(err)
				return "", ""
			}
			oidcConfig := &oidc.Config{
				ClientID: clientID,
			}
			idToken, err := provider.Verifier(oidcConfig).Verify(context.TODO(), myToken.AccessToken)
			if err != nil {
				log.Fatal(err)
				return "", ""
			}

			var outProfile map[string]interface{}
			var outUserInfo map[string]interface{}
			if err := idToken.Claims(&outProfile); err != nil {
				log.Fatal(err)
				return "", ""
			}
			if err := userInfo.Claims(&outUserInfo); err != nil {
				log.Fatal(err)
				return "", ""
			}
			data, err := json.MarshalIndent(outProfile, "", "    ")
			if err != nil {
				log.Fatal(err)
				return "", ""
			}
			data2, err := json.MarshalIndent(outUserInfo, "", "    ")
			if err != nil {
				log.Fatal(err)
				return "", ""
			}
			fmt.Println("Claims from id_token ")
			fmt.Println(string(data))
			fmt.Println("Claims from userinfo call ")
			fmt.Println(string(data2))
		}
	} else {
		if resp.StatusCode != 200 {
			log.Println("Not allowed - check if your client ", clientID, " is public. HTTP code ", resp.Status)
		} else {
			log.Println("Error while getting ID token")
		}
	}
	return accessToken, refreshToken
}

func HandleRefreshFlow(clientID string, clientSecret string, existingRefresh string, refreshExpiry string, provider oidc.Provider) string {
	refreshToken := ""
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	vals := url.Values{}
	vals.Set("grant_type", "refresh_token")
	vals.Set("refresh_token", existingRefresh)
	vals.Set("client_id", clientID)
	if clientSecret != "" {
		vals.Set("client_secret", clientSecret)
	}
	if refreshExpiry != "" {
		vals.Set("refresh_expiry", refreshExpiry)
	}
	req, requestError := http.NewRequest("POST", provider.Endpoint().TokenURL, strings.NewReader(vals.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, clientError := client.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	if result != nil {
		fmt.Print("Result from refresh flow: ")
		fmt.Println(result)
		jsonStr, marshalError := json.Marshal(result)
		if marshalError != nil {
			log.Fatal(marshalError)
		}
		var myToken oauth2.Token
		json.Unmarshal([]byte(jsonStr), &myToken)
		refreshToken = myToken.RefreshToken
	}
	return refreshToken
}
