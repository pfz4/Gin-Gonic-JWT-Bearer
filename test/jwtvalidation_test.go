package test

import (
	"testing"
	"github.com/golang-jwt/jwt"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"bytes"
	"fmt"
	"os"
	"strings"
	"gitlab.pfz4.de/pfz4/gin-gonic-jwtbearer"
	"time"
)


type RSAKeypair struct {
	PrivateKey string
	PublicKey string
}

func createKeypair() *RSAKeypair {
	privatekey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
        fmt.Printf("Cannot generate RSA key\n")
        os.Exit(1)
    }
    publickey := &privatekey.PublicKey

	// dump private key to file
    var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
    privateKeyBlock := &pem.Block{
        Type:  "RSA PRIVATE KEY",
        Bytes: privateKeyBytes,
    }
	privateKeyPem := new(bytes.Buffer)
    err = pem.Encode(privateKeyPem, privateKeyBlock)
    if err != nil {
        fmt.Printf("error when encode private pem: %s \n", err)
        os.Exit(1)
    }

    // dump public key to file
    publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
    if err != nil {
        fmt.Printf("error when dumping publickey: %s \n", err)
        os.Exit(1)
    }
    publicKeyBlock := &pem.Block{
        Type:  "PUBLIC KEY",
        Bytes: publicKeyBytes,
    }
	publicKeyPem := new(bytes.Buffer)
    err = pem.Encode(publicKeyPem, publicKeyBlock)
    if err != nil {
        fmt.Printf("error when encode public pem: %s \n", err)
        os.Exit(1)
    }

	return &RSAKeypair{
		PrivateKey: privateKeyPem.String(),
		PublicKey: publicKeyPem.String(),
	}
}


func createIssuer(keypair *RSAKeypair) *jwtbearer.Issuer {
	publicKey := keypair.PublicKey
	publicKey = strings.Replace(publicKey, "-----BEGIN PUBLIC KEY-----\n", "", -1)
	publicKey = strings.Replace(publicKey, "\n-----END PUBLIC KEY-----", "", -1)
	return &jwtbearer.Issuer{
		Name: "validissuer",
		Realm: "realm",
		PublicKey: publicKey,
		TokenService: "",
		AccountService: "",
		TokensNotBefore: 0,
	}
}
func createJwtBearer(keypair *RSAKeypair) *jwtbearer.JwtBearer{
	return &jwtbearer.JwtBearer{
		Issuer: createIssuer(keypair),
		Audience: "validaudience",
	}
}

func createToken(keypair *RSAKeypair, tokenPayload *jwtbearer.TokenInfo) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, tokenPayload)
	privateKey, _ := jwt.ParseRSAPrivateKeyFromPEM([]byte(keypair.PrivateKey))
	tokenString, _ := token.SignedString(privateKey)

	return tokenString
}


var rsaKeypair *RSAKeypair
var jwtBearer *jwtbearer.JwtBearer

func createStartValuesIfNotPresent(){
	if rsaKeypair==nil{
		rsaKeypair = createKeypair()
	}
	if jwtBearer==nil{
		jwtBearer = createJwtBearer(rsaKeypair)
	}
}


func TestAudienceValidation(t *testing.T){
	createStartValuesIfNotPresent()
	testTokenInfo :=  &jwtbearer.TokenInfo{}
	testTokenInfo.Issuer="validissuer"

	testTokenInfo.Audience=[]string{"invalidaudience", "invalidaudience2"}
	token := createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ := jwtBearer.GetTokenInfoFromString(token)
	if tokenInfo.IsValid {
		t.Errorf("[1] expected invalid token, received valid token")
	}

	testTokenInfo.Audience=[]string{"validaudience", "invalidaudience"}
	token = createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ = jwtBearer.GetTokenInfoFromString(token)
	if !tokenInfo.IsValid {
		t.Errorf("[2] expected valid token, received invalid token: %s", tokenInfo.ErrorMessage)
	}

	testTokenInfo.Audience=[]string{"ibvalidaudience", "validaudience"}
	token = createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ = jwtBearer.GetTokenInfoFromString(token)
	if !tokenInfo.IsValid {
		t.Errorf("[3] expected valid token, received invalid token: %s", tokenInfo.ErrorMessage)
	}
}

func TestIssuerValidation(t *testing.T){
	createStartValuesIfNotPresent()
	testTokenInfo :=  &jwtbearer.TokenInfo{}
	testTokenInfo.Audience=[]string{"validaudience"}

	testTokenInfo.Issuer="invalidissuer"
	token := createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ := jwtBearer.GetTokenInfoFromString(token)
	if tokenInfo.IsValid {
		t.Errorf("[1] expected invalid token, because Issuer is invalid, received valid token: %s", tokenInfo.ErrorMessage)
	}

	testTokenInfo.Issuer="validissuer"
	token = createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ = jwtBearer.GetTokenInfoFromString(token)
	if !tokenInfo.IsValid {
		t.Errorf("[2] expected valid token, received invalid token: %s", tokenInfo.ErrorMessage)
	}
}

func TestOriginValidation(t *testing.T){
	createStartValuesIfNotPresent()
	testTokenInfo :=  &jwtbearer.TokenInfo{}
	testTokenInfo.Issuer="validissuer"
	testTokenInfo.Audience=[]string{"validaudience"}

	testTokenInfo.AllowedOrigins=[]string{"https://example.com"}
	token := createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ := jwtBearer.GetTokenInfoFromString(token)
	tokenInfo = jwtBearer.ValidateOrigin(tokenInfo, "https://example.com")
	if !tokenInfo.IsValid {
		t.Errorf("[1] expected valid token, received invalid token: %s", tokenInfo.ErrorMessage)
	}

	testTokenInfo.AllowedOrigins=[]string{"https://example.com"}
	token = createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ = jwtBearer.GetTokenInfoFromString(token)
	tokenInfo = jwtBearer.ValidateOrigin(tokenInfo, "https://example.com/test")
	if tokenInfo.IsValid {
		t.Errorf("[2] expected invalid token, received valid token: %s", tokenInfo.ErrorMessage)
	}

	testTokenInfo.AllowedOrigins=[]string{"https://example.com"}
	token = createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ = jwtBearer.GetTokenInfoFromString(token)
	tokenInfo = jwtBearer.ValidateOrigin(tokenInfo, "http://example.com")
	if tokenInfo.IsValid {
		t.Errorf("[3] expected invalid token, received valid token: %s", tokenInfo.ErrorMessage)
	}

	testTokenInfo.AllowedOrigins=[]string{"https://example.com/*"}
	token = createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ = jwtBearer.GetTokenInfoFromString(token)
	tokenInfo = jwtBearer.ValidateOrigin(tokenInfo, "https://example.com/test")
	if !tokenInfo.IsValid {
		t.Errorf("[4] expected valid token, received invalid token: %s", tokenInfo.ErrorMessage)
	}
}

func TestTokenExpiration(t *testing.T){
	createStartValuesIfNotPresent()
	testTokenInfo :=  &jwtbearer.TokenInfo{}
	testTokenInfo.Issuer="validissuer"
	testTokenInfo.Audience=[]string{"validaudience"}

	testTokenInfo.ExpiresAt = time.Now().Unix()+60
	token := createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ := jwtBearer.GetTokenInfoFromString(token)
	if !tokenInfo.IsValid {
		t.Errorf("[1] expected valid token, received invalid token: %s", tokenInfo.ErrorMessage)
	}

	testTokenInfo.ExpiresAt = time.Now().Unix()-60
	token = createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ = jwtBearer.GetTokenInfoFromString(token)
	if tokenInfo.IsValid {
		t.Errorf("[1] expected invalid token, received valid token: %s", tokenInfo.ErrorMessage)
	}

}

func TestTokenNotBefore(t *testing.T){
	createStartValuesIfNotPresent()
	testTokenInfo :=  &jwtbearer.TokenInfo{}
	testTokenInfo.Issuer="validissuer"
	testTokenInfo.Audience=[]string{"validaudience"}

	testTokenInfo.NotBefore = time.Now().Unix()
	token := createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ := jwtBearer.GetTokenInfoFromString(token)
	if !tokenInfo.IsValid {
		t.Errorf("[1] expected valid token, received invalid token: %s", tokenInfo.ErrorMessage)
	}

	testTokenInfo.NotBefore = time.Now().Unix()+60
	token = createToken(rsaKeypair, testTokenInfo)
	tokenInfo, _ = jwtBearer.GetTokenInfoFromString(token)
	if tokenInfo.IsValid {
		t.Errorf("[1] expected invalid token, received valid token: %s", tokenInfo.ErrorMessage)
	}

}