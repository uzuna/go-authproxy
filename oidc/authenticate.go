package oidc

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
	"github.com/uzuna/go-authproxy/internal/nonce"
)

func NewAuthenticator(c *Config) (Authenticator, error) {
	set, err := jwk.FetchHTTP(c.JWKURL)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	kf, err := MakeKeyfunc(set)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &authenticator{
		ns:      nonce.NewStore(time.Second * 60),
		config:  c,
		keyfunc: kf,
	}, nil
}

type authenticator struct {
	ns      nonce.Store
	config  *Config
	keyfunc jwt.Keyfunc
}

// AuthURL gengerates Authorize url
func (a *authenticator) AuthURL(state string, opts ...URLOptionalParameter) (string, error) {
	// input validation
	if len(state) < 1 {
		return "", errors.Errorf("Must set state")
	}

	// build URL
	c := a.config
	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)

	v := url.Values{
		"response_type": {c.ResponseType},
		"client_id":     {c.ClientID},
		"state":         {state},
		"nonce":         {a.ns.Get()},
	}
	if c.RedirectURL != "" {
		v.Set("redirect_uri", c.RedirectURL)
	}
	if len(c.Scopes) > 0 {
		v.Set("scope", strings.Join(c.Scopes, " "))
	}
	for _, x := range opts {
		x.setValue(v)
	}
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}

	buf.WriteString(v.Encode())
	return buf.String(), nil
}

func (a *authenticator) Authenticate(r *http.Request) (*AuthResponse, error) {
	ares, err := ParseAuthResponse(r)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	claims, err := ParseIDToken(ares.IDToken, a.keyfunc)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	if !a.ns.CheckOnce(claims.Nonce) {
		return nil, errors.Errorf("Invalid nonce")
	}

	// @TODO switch grant flow
	// c := a.config
	// if strings.Contains(c.ResponseType, "code") && len(ares.Code) > 0 {
	// 	//
	// }

	return ares, nil
}
