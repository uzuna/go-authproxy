package oidc

import (
	"fmt"
	"io/ioutil"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
)

type idTokenClaims struct {
	Issuer      string `json:"iss"`
	Subject     string `json:"sub"`
	Audience    string `json:"aud"`
	Nonce       string `json:"nonce"`
	ExpireInt   int64  `json:"exp"`
	IssuedAtInt int64  `json:"iat"`
	AuthTime    int64  `json:"auth_time"`
}

// Valid is check field and format specification
// 書式と要素が正しいことを確認する
func (c *idTokenClaims) Valid() error {

	if len(c.Nonce) < 1 {
		return errors.Errorf("Not found nonce")
	}
	if len(c.Audience) < 1 {
		return errors.Errorf("Not found audience")
	}
	if len(c.Issuer) < 1 {
		return errors.Errorf("Not found Issuer")
	}
	if c.IssuedAtInt < 1 {
		return errors.Errorf("Not found iat")
	}
	if c.ExpireInt < 1 {
		return errors.Errorf("Not found exp")
	}
	if c.AuthTime < 1 {
		return errors.Errorf("Not found auth_time")
	}
	return nil
}

func (c *idTokenClaims) Expire() time.Time {
	return time.Unix(c.ExpireInt, 0)
}

func (c *idTokenClaims) IssuedAt() time.Time {
	return time.Unix(c.IssuedAtInt, 0)
}

func TestIDToken(t *testing.T) {

	b, err := ioutil.ReadFile("./testdata/jwk.json")
	checkError(t, errors.WithStack(err))
	jwkset, err := jwk.Parse(b)
	checkError(t, errors.WithStack(err))

	b, err = ioutil.ReadFile("./testdata/idtoken_sample.txt")
	checkError(t, errors.WithStack(err))
	idTokenStr := string(b)

	p := &jwt.Parser{}
	var claims idTokenClaims

	f := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			// Check kid
			kid, ok := token.Header["kid"]
			if !ok {
				return nil, fmt.Errorf("Has not kid property")
			}
			key := jwkset.LookupKeyID(kid.(string))
			if len(key) < 1 {
				return nil, fmt.Errorf("Unknown kid: %s", kid)
			}
			return key[0].Materialize()
		}
		return nil, fmt.Errorf("Ignore algorithem [%s]", token.Header["alg"])
	}
	_, err = p.ParseWithClaims(idTokenStr, &claims, f)
	checkError(t, errors.WithStack(err))
	t.Logf("%v", claims)
	t.Logf("%v", claims.Expire())
}

func checkError(t *testing.T, err error) {
	if err != nil {
		t.Logf("%+v", err)
		t.FailNow()
	}
}
