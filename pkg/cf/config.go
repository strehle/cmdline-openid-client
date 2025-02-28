package cf

import (
	"encoding/json"
	"fmt"
	"github.com/strehle/cmdline-openid-client/pkg/client"
	"io/ioutil"
	"os"
	"strings"
)

type CFUAA struct {
	UAAEndpoint          string `json:"UaaEndpoint"`
	UAAOAuthClient       string `json:"UAAOAuthClient"`
	UAAOAuthClientSecret string `json:"UAAOAuthClientSecret"`
}

func ReadUaaConfig() CFUAA {
	var configFile CFUAA

	var cfFile = ConfigFilePath()
	jsonFile, err := os.Open(cfFile)
	if err != nil {
		return configFile
	}
	defer jsonFile.Close()
	byteResult, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal([]byte(byteResult), &configFile)
	if configFile.UAAEndpoint != "" {
		configFile.UAAEndpoint = configFile.UAAEndpoint + "/oauth/token"
	}
	return configFile
}

func WriteUaaConfig(issuer string, token client.OpenIdToken) bool {
	if token.AccessToken == "" || token.RefreshToken == "" {
		return false
	}
	var jsonMap = make(map[string]interface{})
	var cfFile = ConfigFilePath()
	jsonFile, err := os.Open(cfFile)
	if err != nil {
		return false
	}
	byteResult, _ := ioutil.ReadAll(jsonFile)
	json.Unmarshal([]byte(byteResult), &jsonMap)
	jsonFile.Close()
	// simply ensure that we don't write into cf/config.json with wrong issuer / context
	var calcIssuer = ""
	if jsonMap["UaaEndpoint"] != nil && jsonMap["UaaEndpoint"] != "" {
		calcIssuer = fmt.Sprintf("%v/oauth/token", jsonMap["UaaEndpoint"])
	}
	if jsonMap["UAAOAuthClient"] == nil || jsonMap["UAAOAuthClientSecret"] == nil || calcIssuer == "" || strings.Compare(issuer, calcIssuer) != 0 {
		return false
	}
	// update token entries
	jsonMap["AccessToken"] = "bearer " + token.AccessToken
	jsonMap["RefreshToken"] = token.RefreshToken
	jsonString, _ := json.MarshalIndent(jsonMap, "", "  ")
	err = ioutil.WriteFile(cfFile, jsonString, 0600)
	if err != nil {
		return false
	}
	return true
}
