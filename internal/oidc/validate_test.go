package oidc

import (
	"io/ioutil"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/uzuna/go-authproxy/internal/nonce"
)

func TestIDToken(t *testing.T) {

	b, err := ioutil.ReadFile("./testdata/jwk.json")
	checkError(t, errors.WithStack(err))
	f, err := getJWK(b)
	checkError(t, errors.WithStack(err))

	b, err = ioutil.ReadFile("./testdata/idtoken_sample.txt")
	checkError(t, errors.WithStack(err))
	idTokenStr := string(b)

	claims, err := ParseIDToken(idTokenStr, f)
	checkError(t, errors.WithStack(err))
	assert.Equal(t, "s6BhdRkqt3", claims.Audience)
	assert.True(t, claims.Expire().Equal(time.Unix(1311281970, 0)), "Un match ExpireAt")
	assert.True(t, claims.IssuedAt().Equal(time.Unix(1311280970, 0)), "Un match IssuedAt")

	ns := nonce.NewStore(time.Second * 10)
	vr, err := NewIDTokenValidator([]string{claims.Issuer}, []string{claims.Audience}, ns)
	checkError(t, errors.WithStack(err))
	t.Logf("%v", vr.Validate(claims))
}

func checkError(t *testing.T, err error) {
	if err != nil {
		t.Logf("%+v", err)
		t.FailNow()
	}
}
