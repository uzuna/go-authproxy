package authproxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net/http"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"

	"golang.org/x/oauth2"
)

// Validate is Oauth Token Check
// jwk check
func Validate(oc *oauth2.Config, jwtParser func(token *jwt.Token) (interface{}, error)) func(http.Handler) http.Handler {

	ca := &ContextAccess{}
	type AuthCodes struct {
		IDToken string
		Code    string
		State   string
	}
	return func(next http.Handler) http.Handler {

		errorBind := func(w http.ResponseWriter, r *http.Request, er *authResult) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, CtxAuthResult, er)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		fn := func(w http.ResponseWriter, r *http.Request) {
			var ac AuthCodes
			// form_check
			err := r.ParseForm()
			if err != nil {
				er := &authResult{
					ErrCode: errInvalidBody,
					Message: "Has not post body",
				}
				errorBind(w, r, er)
				return
			}
			ac = AuthCodes{
				IDToken: r.Form.Get("id_token"),
				Code:    r.Form.Get("code"),
				State:   r.Form.Get("state"),
			}

			// id_token check
			if len(ac.IDToken) < 1 {
				er := &authResult{
					ErrCode: errInvalidBody,
					Message: "Has not id_token",
				}
				errorBind(w, r, er)
				return
			}

			// get session data and check state
			ses, err := ca.Session(r)
			if err != nil {
				er := &authResult{
					ErrCode: errFailSession,
					Message: "Can not use session",
				}
				errorBind(w, r, er)
				return
			}
			if ac.State != ses.Values[sesState].(string) {
				er := &authResult{
					ErrCode: errInvalidBody,
					Message: "Unmatch state",
				}
				errorBind(w, r, er)
				return
			}
			delete(ses.Values, sesState)

			// validate idtoken
			_, err = jwt.Parse(ac.IDToken, jwtParser)
			if err != nil {
				er := &authResult{
					ErrCode: errInvalidBody,
					Message: err.Error(),
				}
				errorBind(w, r, er)
				return
			}

			// Request Access Token and save that
			exctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			ot, err := oc.Exchange(exctx, ac.Code)
			if err != nil {
				er := &authResult{
					ErrCode: errFailGetToken,
					Message: err.Error(),
				}
				errorBind(w, r, er)
				return
			}

			// Check ID Token and save in session
			uinfo, err := createUserInfo(ac.IDToken, ot)
			uinfo.Token = ot
			if err != nil {
				er := &authResult{
					ErrCode: errFailGetToken,
					Message: err.Error(),
				}
				errorBind(w, r, er)
				return
			}
			ses.Values[sesUserInfo] = uinfo

			// save session state
			err = ses.Save(r, w)
			if err != nil {
				er := &authResult{
					ErrCode: errFailSession,
					Message: err.Error(),
				}
				errorBind(w, r, er)
				return
			}

			ctx := r.Context()
			er := &authResult{ErrCode: errLogIn}
			ctx = context.WithValue(ctx, CtxAuthResult, er)
			next.ServeHTTP(w, r.WithContext(ctx))
		}

		return http.HandlerFunc(fn)
	}
}

func createUserInfo(ts string, ot *oauth2.Token) (*UserSessionInfo, error) {
	p := &jwt.Parser{}
	m := jwt.MapClaims{}
	_, _, err := p.ParseUnverified(ts, m)
	if err != nil {
		return nil, err
	}
	return &UserSessionInfo{
		Email:  m["email"].(string),
		Expire: ot.Expiry,
		Token:  ot,
	}, nil
}

// AuthCodeURL generate authurl and return using state
func AuthCodeURL(oc *oauth2.Config, ns *NonceStore) (url, state string, err error) {
	// state生成
	stateBytes := make([]byte, 16)
	_, err = rand.Read(stateBytes)
	if err != nil {
		return "", "", err
	}
	state = fmt.Sprintf("%x", stateBytes)

	// get nonce
	nonce := ns.Get()

	// gen address
	adrs := oc.AuthCodeURL(state,
		oauth2.SetAuthURLParam("scope", "openid"),
		oauth2.SetAuthURLParam("response_mode", "form_post"),
		oauth2.SetAuthURLParam("response_type", "id_token code"),
		oauth2.SetAuthURLParam("nonce", nonce),
	)
	return adrs, state, err
}

func Login(oc *oauth2.Config, ns *NonceStore) http.Handler {
	ca := &ContextAccess{}
	fn := func(w http.ResponseWriter, r *http.Request) {
		adrs, state, err := AuthCodeURL(oc, ns)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// save to session
		ses, err := ca.Session(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		ses.Values[sesState] = state
		err = ses.Save(r, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

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
