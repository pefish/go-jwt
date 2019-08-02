package go_jwt

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/pefish/go-error"
	"time"
)

type JwtClass struct {
}

var Jwt = JwtClass{}

func (this *JwtClass) GetJwt(privKey string, expireDuration time.Duration, payload map[string]interface{}) string {
	token := jwt.New(jwt.GetSigningMethod("RS256"))
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(privKey))
	claims := make(jwt.MapClaims)
	claims["exp"] = time.Now().Add(expireDuration).Unix()
	claims["iat"] = time.Now().Unix() // 颁发时间
	claims["payload"] = payload
	token.Claims = claims
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		go_error.ThrowError(`jwt generate error`, 0, err)
	}
	return tokenString
}

func (this *JwtClass) VerifyJwt(pubKey string, tokenStr string) bool {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		verifyKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKey))
		if err != nil {
			return nil, err
		}
		return verifyKey, nil
	})
	if err != nil {
		go_error.ThrowInternal(`jwt verify error`)
	}
	return token.Valid
}

func (this *JwtClass) VerifyJwtSkipClaimsValidation(pubKey string, tokenStr string) bool {
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
		go_error.ThrowInternal(`jwt verify error`)
	}
	return token.Valid
}

func (this *JwtClass) DecodeBodyOfJwt(tokenStr string) map[string]interface{} {
	claims := jwt.MapClaims{}
	jwt.ParseWithClaims(tokenStr, claims, nil)
	return claims
}

func (this *JwtClass) DecodePayloadOfJwtBody(tokenStr string) map[string]interface{} {
	claims := jwt.MapClaims{}
	jwt.ParseWithClaims(tokenStr, claims, nil)
	return claims[`payload`].(map[string]interface{})
}
