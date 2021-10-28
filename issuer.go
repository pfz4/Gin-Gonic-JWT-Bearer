package jwtbearer
import (
	"net/http"
	"io/ioutil"
	"encoding/json"
	"strings"
)


type Issuer struct {
	Name string `json:"name"`
	Realm string `json:"realm"`
	PublicKey string `json:"public_key"`
	TokenService string `json:"token-service"`
	AccountService string `json:"account-service"`
	TokensNotBefore int `json:"tokens-not-before"`
}

func GetIssuer(issuerUrl string) (*Issuer, error){
	resp, err := http.Get(issuerUrl)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result Issuer
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, err
	}
	result.Name = issuerUrl
	if strings.HasSuffix(result.Name, "/"){
		result.Name=result.Name[:len(result.Name)-1]
	}

	return &result, nil
}