package go_jwt

import (
	"fmt"
	"github.com/pefish/go-test-assert"
	"testing"
	"time"
)

func TestJwtClass_VerifyJwt(t *testing.T) {
	pkey, pubkey, err := GeneRsaKeyPair()
	test.Equal(t, nil, err)
	jwt, err := Jwt.GetJwt(pkey, 60 * time.Second, nil)
	test.Equal(t, nil, err)
	b, _, err := Jwt.VerifyJwt(
		pubkey,
		jwt,
		false)
	test.Equal(t, true, b)
	test.Equal(t, nil, err)
}

func TestJwtClass_GetJwt(t *testing.T) {
	a := Jwt.MustGetJwt("-----BEGIN RSA PRIVATE KEY-----\n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\n-----END RSA PRIVATE KEY-----\n",
6 * time.Hour, nil)
	fmt.Println(a)
	test.Equal(t, true, len(a) > 100)
}

func TestGeneRsaKeyPair(t *testing.T) {
	pkey, pubkey, err := GeneRsaKeyPair()
	test.Equal(t, nil, err)
	test.Equal(t, true, len(pkey) > 100)
	test.Equal(t, true, len(pubkey) > 100)
}