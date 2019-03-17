package oidc

import (
	"net/http"
	"net/url"
	"time"
)

const (
	// ResponceTypeCode    = ResponceType("code")
	// ResponceTypeToken   = ResponceType("token")
	// ResponceTypeIDTOken = ResponceType("id_token")

	TokenTypeIDToken = iota
	TokenTypeAccessToken
	TokenTypeRefreshToken
)

type ResponceType string

type Token interface {
	Token() (token string, tokenType int)
	Get(tokenType int) (token string)
	ExpireAt() (time.Duration, bool)
	Refresh() error
}

type Authenticator interface {
	AuthURL(state string) (string, error)
	Validate(req *http.Request) (Token, error)
}

type Config struct {
	ClientID     string
	ClientSecret string
	Endpoint     Endpoint
	RedirectURL  string
	JWKURL       string
	Scopes       []string
	ResponseType string
}

type Endpoint struct {
	AuthURL  string
	TokenURL string
}

// URLOptionalParameter godoc
// idea from oauth2 AuthCodeOption
type URLOptionalParameter interface {
	setValue(url.Values)
}
type setParam struct{ k, v string }

func (p setParam) setValue(m url.Values) { m.Set(p.k, p.v) }

// SetURLParam builds an URLOptionalParameter which passes key/value parameters
func SetURLParam(key, value string) URLOptionalParameter {
	return setParam{key, value}
}
