package oidc_test

import (
	"io/ioutil"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/uzuna/go-authproxy/internal/oidc"
)

const (
	sampleNonce = "n-0S6_WzA2Mj"
)

func TestIDToken(t *testing.T) {

	b, err := ioutil.ReadFile("./testdata/jwk.json")
	checkError(t, errors.WithStack(err))
	f, err := oidc.ParseJWK(b)
	checkError(t, errors.WithStack(err))

	b, err = ioutil.ReadFile("./testdata/idtoken_sample.txt")
	checkError(t, errors.WithStack(err))
	idTokenStr := string(b)

	claims, err := oidc.ParseIDToken(idTokenStr, f)
	checkError(t, errors.WithStack(err))
	assert.Equal(t, "s6BhdRkqt3", claims.Audience)
	assert.True(t, claims.Expire().Equal(time.Unix(1311281970, 0)), "Un match ExpireAt")
	assert.True(t, claims.IssuedAt().Equal(time.Unix(1311280970, 0)), "Un match IssuedAt")

	// ns := nonce.NewStore(time.Second * 10)
	ns := &DummyNonceStore{}
	vr, err := oidc.NewIDTokenValidator([]string{claims.Issuer}, []string{claims.Audience}, ns)
	checkError(t, errors.WithStack(err))
	err = vr.Validate(claims)
	// test tokenは期限切れしているがそれ以外は正しいと返す
	assert.True(t, strings.Contains(err.Error(), "Expired"))
}

func checkError(t *testing.T, err error) {
	if err != nil {
		t.Logf("%+v", err)
		t.FailNow()
	}
}

type DummyNonceStore struct{}

func (s *DummyNonceStore) Get() string {
	return sampleNonce
}

func (s *DummyNonceStore) CheckOnce(nonce string) bool {
	return sampleNonce == nonce
}
