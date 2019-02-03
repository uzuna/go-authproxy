package authproxy

import (
	"fmt"
	"net/http"
	"reflect"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/sessions"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

func NewAuthenticateHandlers(
	oc *oauth2.Config,
	val *IDTokenValidator,
	store sessions.Store,
	opts ...HandlersOption,
) (AuthenticateHandlers, error) {
	timeout := time.Minute
	a := &openidAuthenticateHandlers{
		oauth2conf:    oc,
		authVaridator: val,
		store:         store,
		sessionName:   "authproxy",
		errorPages:    &ErrorPages{},
		nonceStore:    NewNonceStore(timeout),
	}

	for _, v := range opts {
		err := v(a)
		if err != nil {
			return nil, err
		}
	}
	return a, nil
}

type AuthenticateHandlers interface {
	Session() func(http.Handler) http.Handler
	AuthCodeURL() (adrs string, state string, err error)
	LoginRedirect() http.Handler
	ValidateCredential() func(http.Handler) http.Handler
}

func NewIDTokenValidator(jwkset *jwk.Set, issuer, audiense []string) *IDTokenValidator {
	return &IDTokenValidator{
		jwkset:   jwkset,
		Issuer:   issuer,
		Audience: audiense,
	}
}

// IDTokenValidator Varidate IDToken
type IDTokenValidator struct {
	jwkset   *jwk.Set
	Issuer   []string `json:"iss"`
	Audience []string `json:"aud"`
}

// JWTParser create JWT Token Parseand Validatate func tion
func (a *IDTokenValidator) JWTParser(ns *NonceStore) func(token *jwt.Token) (interface{}, error) {
	return func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {

			// Check Nonce
			nonce, ok := token.Claims.(jwt.MapClaims)["nonce"]
			if !ok {
				return nil, fmt.Errorf("Has not nonce")
			}
			ok = ns.CheckOnce(nonce.(string))
			if !ok {
				return nil, fmt.Errorf("Invalid nonce")
			}

			// CHeck Audience and Issuer
			err := a.Match(token)
			if err != nil {
				return nil, err
			}

			// Check kid
			kid, ok := token.Header["kid"]
			if !ok {
				return nil, fmt.Errorf("Has not kid property")
			}
			key := a.jwkset.LookupKeyID(kid.(string))
			if len(key) < 1 {
				return nil, fmt.Errorf("Unknown kid: %s", kid)
			}
			return key[0].Materialize()
		}
		return nil, fmt.Errorf("Ignore algorithem [%s]", token.Header["alg"])
	}
}

func (a *IDTokenValidator) Match(token *jwt.Token) error {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.Errorf("Fail parse claims. has [%s]", reflect.TypeOf(token.Claims))
	}

	if len(a.Issuer) > 0 {
		iss, ok := claims["iss"].(string)
		if !ok {
			return errors.Errorf("Token has not issuer")
		}
		has := a.has(iss, a.Issuer)
		if !has {
			return errors.Errorf("UnAuthenticated issuer")
		}
	}
	if len(a.Audience) > 0 {
		aud, ok := claims["aud"].(string)
		if !ok {
			return errors.Errorf("Token has not audience")
		}
		has := a.has(aud, a.Audience)
		if !has {
			return errors.Errorf("UnAuthenticated audience")
		}
	}
	return nil
}
func (a *IDTokenValidator) has(target string, list []string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

// openidAuthenticateHandlers is implementation of AuthenticateHandlers
type openidAuthenticateHandlers struct {
	store         sessions.Store
	sessionName   string
	oauth2conf    *oauth2.Config
	authVaridator *IDTokenValidator
	nonceStore    *NonceStore
	errorPages    *ErrorPages
}

func (h *openidAuthenticateHandlers) Session() func(http.Handler) http.Handler {
	return Session(h.store, h.sessionName)
}

func (h *openidAuthenticateHandlers) AuthCodeURL() (string, string, error) {
	return AuthCodeURL(h.oauth2conf, h.nonceStore)
}

func (h *openidAuthenticateHandlers) LoginRedirect() http.Handler {
	ca := &ContextAccess{}
	fn := func(w http.ResponseWriter, r *http.Request) {
		// generate AuthAddress
		adrs, state, err := h.AuthCodeURL()
		if err != nil {
			h.errorPages.Error(w, r, err.Error(), http.StatusInternalServerError)
			return
		}

		// save to session
		ses, err := ca.Session(r)
		if err != nil {
			h.errorPages.Error(w, r, err.Error(), http.StatusInternalServerError)
			return
		}
		ses.Values[sesState] = state
		err = ses.Save(r, w)
		if err != nil {
			h.errorPages.Error(w, r, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, adrs, 302)
	}
	return http.HandlerFunc(fn)
}

func (h *openidAuthenticateHandlers) ValidateCredential() func(http.Handler) http.Handler {
	return Validate(h.oauth2conf, h.authVaridator.JWTParser(h.nonceStore))
}
