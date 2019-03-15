package oidc

import (
	"fmt"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/uzuna/go-authproxy/internal/nonce"

	"github.com/pkg/errors"
)

// IDToken standard parameters
type IDTokenClaims struct {
	Issuer      string `json:"iss"`
	Subject     string `json:"sub"`
	Audience    string `json:"aud"`
	Nonce       string `json:"nonce"`
	ExpireInt   int64  `json:"exp"`
	IssuedAtInt int64  `json:"iat"`
	AuthTime    int64  `json:"auth_time"`
	ACR         string `json:"acr"`
	AMR         string `json:"amr"`
	AZP         string `json:"azp"`
}

// Valid is check field and format specification
// 書式と要素が正しいことを確認する
func (c *IDTokenClaims) Valid() error {
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
	// openid-connect-core-1.0 2. ID Token
	// When a max_age request is made or when auth_time
	// if c.AuthTime < 1 {
	// 	return errors.Errorf("Not found auth_time")
	// }
	return nil
}

func (c *IDTokenClaims) Expire() time.Time {
	return time.Unix(c.ExpireInt, 0)
}

func (c *IDTokenClaims) IssuedAt() time.Time {
	return time.Unix(c.IssuedAtInt, 0)
}

// getJWK is generate jwt instance from jwt data
// return keyfunc is included jwkset
func getJWK(b []byte) (jwt.Keyfunc, error) {
	jwkset, err := jwk.Parse(b)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return func(token *jwt.Token) (interface{}, error) {
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
	}, nil
}

// ParseIDToken godoc
// Parse token and validate specification oidc and verification
func ParseIDToken(token string, kf jwt.Keyfunc) (*IDTokenClaims, error) {
	p := &jwt.Parser{}
	var claims IDTokenClaims
	_, err := p.ParseWithClaims(token, &claims, kf)
	if err != nil {
		return nil, err
	}
	return &claims, nil
}

func NewIDTokenValidator(issuers, clientids []string, ns nonce.Store) (*IDTokenValidator, error) {
	issmap := make(map[string]struct{}, len(issuers))
	climap := make(map[string]struct{}, len(clientids))
	for _, v := range issuers {
		issmap[v] = struct{}{}
	}
	for _, v := range clientids {
		climap[v] = struct{}{}
	}
	return &IDTokenValidator{
		ns:     ns,
		issmap: issmap,
		climap: climap,
	}, nil
}

// IDTokenValidator
type IDTokenValidator struct {
	ns     nonce.Store
	issmap map[string]struct{}
	climap map[string]struct{}
}

func (t *IDTokenValidator) Validate(claims *IDTokenClaims) error {
	// Check Nonce
	if ok := t.ns.CheckOnce(claims.Nonce); !ok {
		return errors.Errorf("Invalid nonce")
	}
	// Check Audience
	if _, ok := t.climap[claims.Audience]; !ok {
		return errors.Errorf("Un match ClientID(Audience)")
	}
	// Check Issuer
	if _, ok := t.issmap[claims.Issuer]; !ok {
		return errors.Errorf("Un match Issuer")
	}

	sub := time.Since(claims.Expire())
	if sub <= time.Duration(0) {
		return errors.Errorf("Expired %s", sub.String())
	}

	return nil
}
