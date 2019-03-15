package oidc

import (
	"net/http"
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

type authenticator struct {
}

type Config struct {
	ClientID     string
	ClientSecret string
	EndPoint     Endpoint
	RedirectURL  string
}

type Endpoint struct {
	AuthURL  string
	TokenURL string
}
