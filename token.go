package jwtbearer

import (
	"github.com/golang-jwt/jwt"
	"fmt"
	"strings"
	"encoding/json"
)

type TokenInfo struct {
	IsValid bool `json:"-"`
	ErrorMessage string `json:"-"`

	AuthenticationTime int `json:"auth_time",omitempty`
	Type string `json:"typ",omitempty`
	AuthorizedParty string `json:"azp",omitempty`
	SessionState string `json:"session_state",omitempty`
	AuthenticationContextClass string `json:"acr",omitempty`
	AllowedOrigins []string `json:"allowed-origins",omitempty`
	ResourceAccess map[string]interface{} `json:"resource_access",omitempty`
	Scope string `json:"scope",omitempty`
	EmailVerified bool `json:"email_verified",omitempty`
	Roles  []string `json:"roles",omitempty`
	Name string `json:"name",omitempty`
	PreferredUsername string `json:"preferred_username",omitempty`
	GivenName string `json:"given_name",omitempty`
	FamilyName string `json:"family_name",omitempty`
	Email string `json:"email",omitempty`
	jwt.StandardClaims
}

func (conf *JwtBearer)GetTokenInfoFromString(tokenString string)(*TokenInfo,error){
		//Bring Public Key into correct format
		formattedPublicKey := "-----BEGIN PUBLIC KEY-----\n"
		for index, char := range conf.Issuer.PublicKey {
			formattedPublicKey+=string(char)
			if index % 64 == 63{
				formattedPublicKey+="\n"
			}
		}
		formattedPublicKey+="\n-----END PUBLIC KEY-----"
	
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(formattedPublicKey))
		if err != nil {
			fmt.Println(err)
			return nil, err;
		}
	
		tokenInfo := TokenInfo{}
		tokenInfo.IsValid=true;
		token, err := jwt.ParseWithClaims(tokenString, &tokenInfo, func(token *jwt.Token) (interface{}, error) {
			// Don't forget to validate the alg is what you expect:
			if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
			}
		
			return publicKey, nil
		})
		if err != nil {
			fmt.Println(err)
			return &TokenInfo{
				IsValid: false,
				ErrorMessage: "The Token is invalid",
			}, err;
		}

		audiences := []string{tokenInfo.Audience}
		err = json.Unmarshal([]byte(tokenInfo.Audience), &audiences)

		if (!sliceContainsValue(audiences,conf.Audience))&&conf.Audience!=""{
			tokenInfo.IsValid=false
			tokenInfo.ErrorMessage="The Token Audience is invalid"
		}
		if tokenInfo.Issuer!=conf.Issuer.Name{
			tokenInfo.IsValid=false
			tokenInfo.ErrorMessage="The Token Issuer is invalid"
		}
		if !token.Valid{
			tokenInfo.IsValid=false
			tokenInfo.ErrorMessage="The Token is invalid or expired"
		}
	
		return &tokenInfo, nil
}

func (conf *JwtBearer)GetTokenInfoFromAuthHeader(authHeader string)(*TokenInfo, error){
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token==authHeader {
		return &TokenInfo{
			IsValid: false,
			ErrorMessage: "Could not find Token in Authorization Header",
		}, nil
	}
	return conf.GetTokenInfoFromString(token)
}

func (conf *JwtBearer)ValidateOrigin(tokenInfo *TokenInfo, originHeader string)(*TokenInfo){
	if originHeader != ""{
		if !matchWildcardSlice(tokenInfo.AllowedOrigins, originHeader ){
			tokenInfo.IsValid=false
			tokenInfo.ErrorMessage = "Invalid Request Origin"
			return tokenInfo
		}
	}
	return tokenInfo
}