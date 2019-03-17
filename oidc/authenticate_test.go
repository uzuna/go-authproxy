package oidc

import (
	"io/ioutil"
	"testing"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
)

const (
	sampleNonce = "n-0S6_WzA2Mj"
)

func TestAuthenticate(t *testing.T) {
	// build authenticator
	b, err := ioutil.ReadFile("./testdata/jwk.json")
	checkError(t, errors.WithStack(err))
	f, err := ParseJWK(b)
	a := &authenticator{
		ns: &DummyNonceStore{},
		config: &Config{
			ClientID: "s6BhdRkqt3",
			Endpoint: Endpoint{
				AuthURL:  "https://server.example.com/authorize",
				TokenURL: "https://server.example.com/token",
			},
			RedirectURL:  "https://client.example.com/cb",
			JWKURL:       "https://server.example.com/keys",
			Scopes:       []string{"openid"},
			ResponseType: "id_token",
		},
		keyfunc: f,
	}

	state := "af0ifjsldkj"
	authURL, err := a.AuthURL(state)
	checkError(t, err)

	referenceURL := `https://server.example.com/authorize?client_id=s6BhdRkqt3&nonce=n-0S6_WzA2Mj&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcb&response_type=id_token&scope=openid&state=` + state

	assert.Equal(t, referenceURL, authURL)
}

type DummyNonceStore struct{}

func (s *DummyNonceStore) Get() string {
	return sampleNonce
}

func (s *DummyNonceStore) CheckOnce(nonce string) bool {
	return sampleNonce == nonce
}

func checkError(t *testing.T, err error) {
	if err != nil {
		t.Logf("%+v", err)
		t.FailNow()
	}
}
