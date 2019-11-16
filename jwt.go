package go_jwt

import (
	"github.com/dgrijalva/jwt-go"
	"time"
)

type JwtClass struct {
}

var Jwt = JwtClass{}

func (this *JwtClass) GetJwt(privKey string, expireDuration time.Duration, payload map[string]interface{}) (string, error) {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKey))
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

func (this *JwtClass) MustGetJwt(privKey string, expireDuration time.Duration, payload map[string]interface{}) string {
	tokenString, err := this.GetJwt(privKey, expireDuration, payload)
	if err != nil {
		panic(err)
	}
	return tokenString
}

func (this *JwtClass) VerifyJwt(pubKey string, tokenStr string) (bool, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKey))
		if err != nil {
			return nil, err
		}
		return verifyKey, nil
	})
	if err != nil {
		return false, err
	}
	return token.Valid, nil
}

func (this *JwtClass) MustVerifyJwt(pubKey string, tokenStr string) bool {
	valid, err := this.VerifyJwt(pubKey, tokenStr)
	if err != nil {
		panic(err)
	}
	return valid
}

func (this *JwtClass) VerifyJwtSkipClaimsValidation(pubKey string, tokenStr string) (bool, error) {
	parser := jwt.Parser{
		SkipClaimsValidation: true,
	}
	token, err := parser.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKey))
		if err != nil {
			return nil, err
		}
		return verifyKey, nil
	})
	if err != nil {
		return false, err
	}
	return token.Valid, nil
}

func (this *JwtClass) MustVerifyJwtSkipClaimsValidation(pubKey string, tokenStr string) bool {
	valid, err := this.VerifyJwtSkipClaimsValidation(pubKey, tokenStr)
	if err != nil {
		panic(err)
	}
	return valid
}

func (this *JwtClass) DecodeBodyOfJwt(tokenStr string) (map[string]interface{}, error) {
	claims := jwt.MapClaims{}
	parser := jwt.Parser{}
	_, _, err := parser.ParseUnverified(tokenStr, claims)
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func (this *JwtClass) MustDecodeBodyOfJwt(tokenStr string) map[string]interface{} {
	result, err := this.DecodeBodyOfJwt(tokenStr)
	if err != nil {
		panic(err)
	}
	return result
}

func (this *JwtClass) MustDecodePayloadOfJwtBody(tokenStr string) map[string]interface{} {
	return this.MustDecodeBodyOfJwt(tokenStr)[`payload`].(map[string]interface{})
}
