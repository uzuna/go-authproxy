package oidc

import (
	"net/http"
	"net/url"
	"time"
)

const (
	expectContentType = "application/x-www-form-urlencoded"

	// ResponceTypeCode    = ResponceType("code")
	// ResponceTypeToken   = ResponceType("token")
	// ResponceTypeIDTOken = ResponceType("id_token")

	// TokenTypeIDToken = iota
	// TokenTypeAccessToken
	// TokenTypeRefreshToken
)

type ResponceType string

type Token interface {
	Token() (token string, tokenType int)
	Get(tokenType int) (token string)
	ExpireAt() (time.Duration, bool)
	Refresh() error
}

type Authenticator interface {
	AuthURL(state string, opts ...URLOptionalParameter) (string, error)
	Authenticate(req *http.Request) (*AuthResponse, error)
	// Validate(req *http.Request) (Token, error)
}

type Config struct {
	ClientID     string   `json:"client_id" yaml:"client_id"`
	ClientSecret string   `json:"client_secret" yaml:"client_secret"`
	Endpoint     Endpoint `json:"endpoint" yaml:"endpoint"`
	RedirectURL  string   `json:"redirect_url" yaml:"redirect_url"`
	JWKURL       string   `json:"jwk_url" yaml:"jwk_url"`
	Scopes       []string `json:"scopes" yaml:"scopes"`
	ResponseType string   `json:"response_type" yaml:"response_type"`
}

type Endpoint struct {
	AuthURL  string `json:"auth_url" yaml:"auth_url"`
	TokenURL string `json:"token_url" yaml:"token_url"`
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
