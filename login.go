package authproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	sesState        = "state"
	SesLoginReferer = "login_referer"
	SesKeyToken     = "jwttoken"
)

type OpenIDToken struct {
	IDToken  string
	Audience string
	Issuer   string
	Subject  string
	Email    string
	Expire   time.Time
	Token    *oauth2.Token
}

type IDTokenAuthorize struct {
	Issuer   []string `json:"iss"`
	Audience []string `json:"aud"`
}

func (a *IDTokenAuthorize) Match(token *jwt.Token) error {
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
			return errors.Errorf("UnAuthorized issuer")
		}
	}
	if len(a.Audience) > 0 {
		aud, ok := claims["aud"].(string)
		if !ok {
			return errors.Errorf("Token has not audience")
		}
		has := a.has(aud, a.Audience)
		if !has {
			return errors.Errorf("UnAuthorized audience")
		}
	}
	return nil
}
func (a *IDTokenAuthorize) has(target string, list []string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

func init() {
	gob.Register(OpenIDToken{})
	gob.Register(oauth2.Token{})
}

// Authorize is Oauth Token Check
// jwk check
func Authorize(set *jwk.Set, oc *oauth2.Config, ns *NonceStore, az *IDTokenAuthorize) func(http.Handler) http.Handler {
	jwtParser := func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			kid, ok := token.Header["kid"]
			if !ok {
				return nil, fmt.Errorf("Has not kid property")
			}
			nonce, ok := token.Claims.(jwt.MapClaims)["nonce"]
			if !ok {
				return nil, fmt.Errorf("Has not nonce")
			}
			ok = ns.CheckOnce(nonce.(string))
			if !ok {
				return nil, fmt.Errorf("Invalid nonce")
			}

			// Audience Issuer
			err := az.Match(token)
			if err != nil {
				return nil, err
			}

			key := set.LookupKeyID(kid.(string))
			if len(key) < 1 {
				return nil, fmt.Errorf("Unknown kid: %s", kid)
			}
			return key[0].Materialize()
		}
		return nil, fmt.Errorf("Ignore algorithem [%s]", token.Header["alg"])
	}

	type AuthCodes struct {
		IDToken string
		Code    string
		State   string
	}
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			var ac AuthCodes
			// form_check
			err := r.ParseForm()
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			} else {
				ac = AuthCodes{
					IDToken: r.Form.Get("id_token"),
					Code:    r.Form.Get("code"),
					State:   r.Form.Get("state"),
				}
			}
			// id_token check
			if len(ac.IDToken) < 1 {
				er := &ErrorRecord{
					Code:    StatusInvalidBody,
					Message: "Has not id_token",
				}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// get session data and check state
			ses := r.Context().Value(CtxSession).(*sessions.Session)
			if ac.State != ses.Values[sesState].(string) {
				er := &ErrorRecord{
					Code:    StatusInvalidBody,
					Message: "Unmatch state",
				}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			delete(ses.Values, sesState)

			// validate jwt
			_, err = jwt.Parse(ac.IDToken, jwtParser)
			if err != nil {
				er := &ErrorRecord{
					Code:    StatusInvalidBody,
					Message: err.Error(),
				}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Request Access Token and save that
			exctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			ot, err := oc.Exchange(exctx, ac.Code)
			if err != nil {
				er := &ErrorRecord{
					Code:    StatusFailGetToken,
					Message: err.Error(),
				}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Check ID Token and save in session
			idt, err := ParseIDToken(ac.IDToken)
			idt.Token = ot
			if err != nil {
				er := &ErrorRecord{
					Code:    StatusFailGetToken,
					Message: err.Error(),
				}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			ses.Values[SesKeyToken] = idt

			// save session state
			err = ses.Save(r, w)
			if err != nil {
				er := &ErrorRecord{
					Code:    StatusFailSession,
					Message: err.Error(),
				}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			ctx := r.Context()
			er := &ErrorRecord{Code: StatusLogIn}
			ctx = context.WithValue(ctx, CtxErrorRecord, er)
			next.ServeHTTP(w, r.WithContext(ctx))
		}

		return http.HandlerFunc(fn)
	}
}

func ParseIDToken(ts string) (*OpenIDToken, error) {
	p := &jwt.Parser{}
	m := jwt.MapClaims{}
	_, _, err := p.ParseUnverified(ts, m)
	if err != nil {
		return nil, err
	}
	exp := time.Unix(int64(m["exp"].(float64)), 0)
	return &OpenIDToken{
		IDToken:  ts,
		Audience: m["aud"].(string),
		Issuer:   m["iss"].(string),
		Subject:  m["sub"].(string),
		Expire:   exp,
		Email:    m["email"].(string),
	}, nil
}

func Login(oc *oauth2.Config, ns *NonceStore) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		var err error
		// state生成
		stateBytes := make([]byte, 16)
		_, err = rand.Read(stateBytes)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		state := fmt.Sprintf("%x", stateBytes)

		// save to session
		ses := r.Context().Value(CtxSession).(*sessions.Session)
		ses.Values[sesState] = state

		err = ses.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		nonce := ns.Get()

		// gen address
		adrs := oc.AuthCodeURL(state,
			oauth2.SetAuthURLParam("scope", "openid"),
			oauth2.SetAuthURLParam("response_mode", "form_post"),
			oauth2.SetAuthURLParam("response_type", "id_token code"),
			oauth2.SetAuthURLParam("nonce", nonce),
		)

		http.Redirect(w, r, adrs, 302)
	}
	return http.HandlerFunc(fn)
}

// parse json web key from io.Reader
func ParseKeys(r io.Reader) (*jwk.Set, error) {
	b := new(bytes.Buffer)
	_, err := io.Copy(b, r)
	if err != nil {
		return nil, err
	}
	return jwk.Parse(b.Bytes())
}
