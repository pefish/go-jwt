package go_jwt

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/dgrijalva/jwt-go"
	"time"
)

type JwtClass struct {
}

var Jwt = JwtClass{}

func (jwtInstance *JwtClass) GetJwt(privKey string, expireDuration time.Duration, payload map[string]interface{}) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKey))
	if err != nil {
		return ``, err
	}
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(expireDuration).Unix()
	claims["iat"] = time.Now().Unix() // 颁发时间
	claims["payload"] = payload
	token.Claims = claims
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return ``, err
	}
	return tokenString, nil
}

func (jwtInstance *JwtClass) MustGetJwt(privKey string, expireDuration time.Duration, payload map[string]interface{}) string {
	tokenString, err := jwtInstance.GetJwt(privKey, expireDuration, payload)
	if err != nil {
		panic(err)
	}
	return tokenString
}

func (jwtInstance *JwtClass) VerifyJwt(pubKey string, tokenStr string, skipClaimsValidation bool) (bool, *jwt.Token, error) {
	parser := jwt.Parser{
		SkipClaimsValidation: skipClaimsValidation,
	}
	token, err := parser.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKey))
		if err != nil {
			return nil, err
		}
		return verifyKey, nil
	})
	if err != nil {
		return false, nil, err
	}
	return token.Valid, token, nil
}

func (jwtInstance *JwtClass) MustVerifyJwt(pubKey string, tokenStr string, skipClaimsValidation bool) (bool, *jwt.Token) {
	valid, token, err := jwtInstance.VerifyJwt(pubKey, tokenStr, skipClaimsValidation)
	if err != nil {
		panic(err)
	}
	return valid, token
}

func (jwtInstance *JwtClass) DecodeBodyOfJwt(tokenStr string) (map[string]interface{}, *jwt.Token, error) {
	claims := jwt.MapClaims{}
	parser := jwt.Parser{}
	token, _, err := parser.ParseUnverified(tokenStr, claims)
	if err != nil {
		return nil, nil, err
	}
	return claims, token, nil
}

func (jwtInstance *JwtClass) MustDecodeBodyOfJwt(tokenStr string) (map[string]interface{}, *jwt.Token) {
	result, token, err := jwtInstance.DecodeBodyOfJwt(tokenStr)
	if err != nil {
		panic(err)
	}
	return result, token
}

func GeneRsaKeyPair() (string, string, error) {
	bits := 2048
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derStream,
	}
	privBuffer := new(bytes.Buffer)
	err = pem.Encode(privBuffer, block)
	if err != nil {
		return "", "", err
	}
	// 生成公钥文件
	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", "", err
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubBuffer := new(bytes.Buffer)
	err = pem.Encode(pubBuffer, block)
	if err != nil {
		return "", "", err
	}
	return privBuffer.String(), pubBuffer.String(), nil
}
