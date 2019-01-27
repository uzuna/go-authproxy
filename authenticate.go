package authproxy

import (
	"crypto/rand"
	"encoding/gob"
	"fmt"
	"net/http"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/pkg/errors"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

const (
	sesState      = "state"
	sesAuthRefere = "auth_refere"
	SesKeyToken   = "jwttoken"
)

type OpenIDToken struct {
	IDToken  string
	Audience string
	Issuer   string
	Subject  string
	Email    string
	Token    *oauth2.Token
}

func init() {
	gob.Register(OpenIDToken{})
	gob.Register(oauth2.Token{})
}

// Oauth Token Check
// jwk check
func Authorize(set *jwk.Set, oc *oauth2.Config, ns *NonceStore) http.Handler {
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
			err = errors.Errorf("Has not id_token")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// get session data and check state
		ses := r.Context().Value(CtxSession).(*sessions.Session)
		if ac.State != ses.Values[sesState].(string) {
			err = errors.Errorf("Invalid match state")
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		delete(ses.Values, sesState)

		// validate jwt
		_, err = jwt.Parse(ac.IDToken, jwtParser)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Request Access Token and save that
		ctx := r.Context()
		ot, err := oc.Exchange(ctx, ac.Code)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		idt, err := ParseIDToken(ac.IDToken)
		idt.Token = ot
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ses.Values[SesKeyToken] = idt

		adrs := "/"
		if a, ok := ses.Values[sesAuthRefere].(string); ok {
			adrs = a
			delete(ses.Values, sesAuthRefere)
		}

		// save session state
		err = ses.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, adrs, 302)
	}

	return http.HandlerFunc(fn)
}

func ParseIDToken(ts string) (*OpenIDToken, error) {
	p := &jwt.Parser{}
	m := jwt.MapClaims{}
	_, _, err := p.ParseUnverified(ts, m)
	if err != nil {
		return nil, err
	}
	return &OpenIDToken{
		IDToken:  ts,
		Audience: m["aud"].(string),
		Issuer:   m["iss"].(string),
		Subject:  m["sub"].(string),
		Email:    m["email"].(string),
	}, nil
}

// func LoginRedirect() func(http.Handler) http.Handler {
// 	return func(next http.Handler) http.Handler {
// 		fn := func(w http.ResponseWriter, r *http.Request) {
// 			ses := r.Context().Value(CtxSession).(*sessions.Session)

// 			// AccessTokenが有効ならnext

// 			// Refreshが有効期限内なら sessionをlockしてRefresh

// 			// Token情報がないならLoginへRedirect
// 			ses.Values[sesAuthRefere] = r.URL.String()
// 			err := ses.Save(r, w)
// 			if err != nil {
// 				http.Error(w, err.Error(), http.StatusInternalServerError)
// 				return
// 			}
// 			http.Redirect(w, r, "/login", 302)
// 		}
// 		return http.HandlerFunc(fn)
// 	}
// }

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
