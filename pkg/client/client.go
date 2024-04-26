package client

import (
	"context"
	"crypto"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
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
	"github.com/google/uuid"
	"golang.org/x/oauth2"
)

type callbackEndpoint struct {
	server         *http.Server
	code           string
	shutdownSignal chan string
}

// take from oauth2.token structure
type OIDC_Token struct {
	// ID token according to OIDC standard, always JWT
	IdToken string `json:"id_token"`
	// AccessToken is the token according to OAuth2 standard, might be opaque or JWT
	AccessToken string `json:"access_token"`
	// RefreshToken is a token that's used by the application
	RefreshToken string `json:"refresh_token,omitempty"`
	raw          interface{}
}

func (h *callbackEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	code := r.URL.Query().Get("code")
	if code != "" {
		h.code = code
		logoutUrl := r.URL.Query().Get("state")
		if logoutUrl != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintln(w, "<html><body>Login is successful, You may logout with: <a href=\""+logoutUrl+"\">Logout</a></body></html>")
		} else {
			fmt.Fprintln(w, "Login is successful, You may close the browser and goto commandline")
		}
	} else {
		fmt.Fprintln(w, "Login is not successful, You may close the browser and try again")
	}
	h.shutdownSignal <- "shutdown"
}

func HandleOpenIDFlow(clientID, clientSecret, callbackURL string, scopeParameter string, refreshExpiry string, tokenFormatParameter string, port string, endsession string, privateKeyJwt string, provider oidc.Provider, tlsClient http.Client) (string, string) {

	refreshToken := ""
	idToken := ""
	authrizationScope := "openid"
	callbackEndpoint := &callbackEndpoint{}
	callbackEndpoint.shutdownSignal = make(chan string)
	server := &http.Server{
		Addr:           ":" + port,
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
	query.Set("state", endsession+"?client_id="+clientID)
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
	fmt.Println("")
	fmt.Println("Authorization code is ", callbackEndpoint.code)

	vals := url.Values{}
	vals.Set("grant_type", "authorization_code")
	vals.Set("code", callbackEndpoint.code)
	vals.Set("redirect_uri", callbackURL)
	vals.Set("code_verifier", codeVerifier)
	vals.Set("token_format", tokenFormatParameter)
	//vals.Set("code_verifier", "01234567890123456789012345678901234567890123456789")
	vals.Set("client_id", clientID)
	if clientSecret != "" {
		vals.Set("client_secret", clientSecret)
	}
	if refreshExpiry != "" {
		vals.Set("refresh_expiry", refreshExpiry)
	}
	if privateKeyJwt != "" {
		vals.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		vals.Set("client_assertion", privateKeyJwt)
	}
	req, requestError := http.NewRequest("POST", provider.Endpoint().TokenURL, strings.NewReader(vals.Encode()))
	if requestError != nil {
		log.Fatal(requestError)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, clientError := tlsClient.Do(req)
	if clientError != nil {
		log.Fatal(clientError)
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	if resp.StatusCode == 200 && result != nil {
		fmt.Println("==========")
		var outBodyMap map[string]interface{}
		json.Unmarshal(result, &outBodyMap)
		resultJson, _ := json.MarshalIndent(outBodyMap, "", "    ")
		fmt.Println("OIDC Response Body")
		fmt.Println(string(resultJson))
		fmt.Println("==========")

		var jsonStr = result
		ctx := context.Background()
		var myToken OIDC_Token
		var stanardToken oauth2.Token
		json.Unmarshal([]byte(jsonStr), &myToken)
		/*
			fmt.Println("Access Token  ", myToken.AccessToken)
			fmt.Println("   ")
			fmt.Println("ID Token      ", myToken.IdToken)
			fmt.Println("   ")
			fmt.Println("Refresh Token ", myToken.RefreshToken)
			fmt.Println("==========")
		*/
		if myToken.AccessToken == "" {
			fmt.Println(string(jsonStr))
		} else {
			// access token
			stanardToken.AccessToken = myToken.AccessToken
			idToken = myToken.IdToken
			// refresh token
			stanardToken.RefreshToken = myToken.RefreshToken
			refreshToken = myToken.RefreshToken
			// Getting now the userInfo
			fmt.Println("Call now UserInfo with access_token")
			userInfo, err := provider.UserInfo(ctx, oauth2.StaticTokenSource(&stanardToken))
			if err != nil {
				log.Fatal(err)
				return "", ""
			}
			oidcConfig := &oidc.Config{
				ClientID: clientID,
			}
			idToken, err := provider.Verifier(oidcConfig).Verify(context.TODO(), myToken.IdToken)
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
			fmt.Println("Claims parsed out from id_token ")
			fmt.Println(string(data))
			fmt.Println("Claims returned from request to userinfo endpoint ")
			fmt.Println(string(data2))
		}
	} else {
		if resp.StatusCode != 200 {
			log.Println("Not allowed - check if your client ", clientID, " is public. HTTP code ", resp.Status)
		} else {
			log.Println("Error while getting ID token")
		}
	}
	return idToken, refreshToken
}

func HandleRefreshFlow(clientID string, clientSecret string, existingRefresh string, refreshExpiry string, privateKeyJwt string, provider oidc.Provider) string {
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
	if privateKeyJwt != "" {
		vals.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		vals.Set("client_assertion", privateKeyJwt)
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

func HandleClientCredential(request url.Values, provider oidc.Provider, tlsClient http.Client) string {
	refreshToken := ""
	request.Set("grant_type", "client_credentials")
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
			fmt.Println("Access Token: " + myToken.AccessToken)
		}
	}
	return refreshToken
}

func CreatePrivateKeyJwt(clientID string, x509Cert x509.Certificate, tokenEndpoint string, privateKey crypto.PrivateKey) (string, error) {
	certSum := sha1.Sum(x509Cert.Raw)
	sha1Sum := base64.RawURLEncoding.EncodeToString(certSum[:])
	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["iss"] = clientID                        // Our clientID
	claims["sub"] = clientID                        // Our clientID
	claims["aud"] = tokenEndpoint                   // The token endpoint of receiver
	claims["exp"] = now.Add(time.Minute * 5).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()                      // The time at which the token was issued.
	claims["jti"] = uuid.New().String()             // The jti

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims) // .SignedString(key)
	token.Header["kid"] = sha1Sum
	token.Header["x5t"] = sha1Sum
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return tokenString, nil
}

func CalculateSha1ThumbPrint(x509Cert x509.Certificate) string {
	certSum := sha1.Sum(x509Cert.Raw)
	return base64.RawURLEncoding.EncodeToString(certSum[:])
}
