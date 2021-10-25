package jwtbearer
import (
	"encoding/json"
	"net/http"
	"io/ioutil"
	"github.com/golang-jwt/jwt"
	"fmt"
	"strings"
	"github.com/gin-gonic/gin"
	"regexp"
)

type Issuer struct {
	Name string `json:"name"`
	Realm string `json:"realm"`
	PublicKey string `json:"public_key"`
	TokenService string `json:"token-service"`
	AccountService string `json:"account-service"`
	TokensNotBefore int `json:"tokens-not-before"`
}

type TokenInfo struct {
	Uid string
	Name string
	Username string
	GivenName string
	FamilyName string
	Email string
	Scopes []string
	Roles []string
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

func (iss *Issuer) GetToken(tokenString string) (*jwt.Token, error){
	//Bring Public Key into correct format
	formattedPublicKey := "-----BEGIN PUBLIC KEY-----\n"
	for index, char := range iss.PublicKey {
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

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
	
		return publicKey, nil
	})
	if err != nil {
		fmt.Println(err)
		return nil, err;
	}

	return token, nil
}

func (iss *Issuer) ValidateToken(audience string) gin.HandlerFunc {
    return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization")
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if token==authHeader {
			c.JSON(http.StatusForbidden, gin.H{"msg":"Could not find Token in Authorization Header"})
			c.Abort()
			return
		}
		jwtToken, err := iss.GetToken(token)
		if err != nil{
			c.JSON(http.StatusForbidden, gin.H{"msg":"Token is invalid"})
			c.Abort()
			return
		}

		claims := jwtToken.Claims.(jwt.MapClaims);

		if c.Request.Header.Get("Origin") != ""{
			if !wildcardSliceContainsValue(getClaimStringSlice(claims,"allowed-origins"), c.Request.Header.Get("Origin") ){
				c.JSON(http.StatusForbidden, gin.H{"msg":"Invalid Request Origin"})
				c.Abort()
				return
			}
		}

		if !(getClaimString(claims, "iss")==iss.Name){
			c.JSON(http.StatusForbidden, gin.H{"msg":"Token contains invalid Issuer"})
			c.Abort()
			return
		}

		
		if !sliceContainsValue(getClaimStringSlice(claims,"aud"), audience){
			c.JSON(http.StatusForbidden, gin.H{"msg":"Token does not contain Audience for this Service"})
			c.Abort()
			return
		}
		


		tokenInfo := TokenInfo{
			Uid: getClaimString(claims, "sub"),
			Name: getClaimString(claims, "name"),
			Username: getClaimString(claims, "preferred_username"),
			GivenName: getClaimString(claims, "given_name"),
			FamilyName: getClaimString(claims, "family_name"),
			Email: getClaimString(claims, "email"),
			Scopes: strings.Split(getClaimString(claims, "scope"), " "),
			Roles: getClaimStringSlice(claims, "roles"),
		}

		c.Set("tokeninfo", tokenInfo)

		c.Next()
	}
}

func sliceContainsValue(slice []string, value string) bool{
	for _, sliceValue := range slice{
		if sliceValue==value{
			return true
		}
	}
	return false
}
func wildcardSliceContainsValue(slice []string, value string) bool{
	for _, sliceValue := range slice{
		if ok,_:=regexp.MatchString(strings.Replace(sliceValue, "*", ".*", -1), value); ok{
			return true
		}
	}
	return false
}

func getClaimString(claims jwt.MapClaims, name string) string {
	value := claims[name]
	switch value.(type) {
		case string:
			return value.(string)
		default:
			return ""
	}
}
func getClaimStringSlice(claims jwt.MapClaims, name string) []string {
	slice := claims[name]
	switch slice.(type) {
		case []interface{}:
			sliceArr := slice.([]interface{})
			output := []string{}
			for _,obj:=range(sliceArr){
				output = append(output,obj.(string))
			}
			return output
		default:
			return []string{}
	}
}