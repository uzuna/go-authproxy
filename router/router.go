package router

import (
	"net/http"
	"regexp"
	"time"

	"github.com/pkg/errors"
	"github.com/uzuna/go-authproxy/errorpage"
	"github.com/uzuna/go-authproxy/internal/session"
	"github.com/uzuna/go-authproxy/oidc"
)

type RouteProvider interface {
	LoadSession() func(next http.Handler) http.Handler
	AuthRedirect() func(next http.Handler) http.Handler
	Authenticate() http.Handler
	Login(ex ExpectRedirectProp) http.Handler

	AuthInfo(r *http.Request) (*session.AuthInfo, error)
}

func ReferrerMatch(re *regexp.Regexp) ExpectRedirectProp {
	return &expectRedirectProp{
		reRef: re,
	}
}

type expectRedirectProp struct {
	reRef *regexp.Regexp
}

func (r expectRedirectProp) Referrer(ref string) bool {
	return r.reRef.MatchString(ref)
}

// ExpectRedirectProp swicth redirect action enable or not
// 意図しないReferrerが入力されるのを防ぐ
type ExpectRedirectProp interface {
	Referrer(string) bool
}

// New creates RouteProvider
func New(auth oidc.Authenticator, astore session.AuthStore, ep *errorpage.ErrorPages, aiKey interface{}) RouteProvider {
	return &router{
		auth:        auth,
		astore:      astore,
		ep:          ep,
		authinfoKey: aiKey,
	}
}

type router struct {
	auth        oidc.Authenticator
	astore      session.AuthStore
	ep          *errorpage.ErrorPages
	authinfoKey interface{}
}

func (rt *router) LoadSession() func(next http.Handler) http.Handler {
	return rt.astore.Handler()
}

// Authenticate recieve authenticate responce
// Recommended to mount on "/cb"
func (rt *router) Authenticate() http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {

		// Parse body and validate key
		ares, err := rt.auth.Authenticate(r)
		if err != nil {
			rt.ep.Error(w, r, err.Error(), 401)
			return
		}

		// Check state from session
		ainfo, err := rt.AuthInfo(r)
		if err != nil {
			rt.ep.Error(w, r, err.Error(), 503)
			return
		}

		if ares.State != ainfo.AuthenticationState {
			err = errors.Errorf("Unmatch state")
			rt.ep.Error(w, r, err.Error(), 401)
			return
		}

		// Redirect to referrer
		redirectPath := "/"
		if len(ainfo.LoginReferer) > 0 {
			redirectPath = ainfo.LoginReferer
		}
		ainfo.AuthenticationState = ""
		ainfo.IDToken = ares.IDToken
		ainfo.ExpireAt = ares.Claims.Expire()
		ainfo.LoggedIn = true

		// Aave auth information
		err = rt.astore.Save(w, r, ainfo)
		if err != nil {
			rt.ep.Error(w, r, err.Error(), 503)
			return
		}

		// Return to Top
		w.Header().Set("Location", redirectPath)
		w.WriteHeader(http.StatusSeeOther)
	}
	return http.HandlerFunc(fn)
}

// Login generate handler of OIDC Login redirecter
// Recommended to mount on "/login"
func (rt *router) Login(ex ExpectRedirectProp) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// Check authinfo
		ainfo, err := rt.AuthInfo(r)
		if err != nil {
			rt.ep.Error(w, r, err.Error(), 503)
			return
		}
		// I loggedin and not expired return home
		if ainfo.LoggedIn && time.Since(ainfo.ExpireAt) < time.Duration(0) {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		// generate URL
		state := oidc.GenState()
		ainfo.AuthenticationState = state

		// 期待するReferrer値の場合はLogin成功後のリダイレクト先に入れる
		referrer := r.Header.Get("Referer")
		if ex.Referrer(referrer) {
			ainfo.LoginReferer = referrer
		}
		authpath, err := rt.auth.AuthURL(state,
			oidc.SetURLParam("response_mode", "form_post"),
		)
		if err != nil {
			rt.ep.Error(w, r, err.Error(), 503)
			return
		}
		err = rt.astore.Save(w, r, ainfo)
		if err != nil {
			rt.ep.Error(w, r, err.Error(), 503)
			return
		}

		w.Header().Set("Location", authpath)
		w.WriteHeader(http.StatusFound)
	}
	return http.HandlerFunc(fn)
}

// AuthRedirect rejects unauthenticated access and prompt login
// Recommended to insert at the beginning of the certification route
func (rt *router) AuthRedirect() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ainfo, err := rt.AuthInfo(r)
			if err != nil {
				rt.ep.Error(w, r, err.Error(), 503)
				return
			}
			// Show Login page when not loggedin
			// 301だとRefererが取れないため401ページを中継する
			if !ainfo.LoggedIn || time.Since(ainfo.ExpireAt) > time.Second {
				rt.ep.Error(w, r, "Please Login.", 401)
				return
			}
			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func (rt *router) AuthInfo(r *http.Request) (*session.AuthInfo, error) {
	ainfo, ok := r.Context().Value(rt.authinfoKey).(*session.AuthInfo)
	if !ok {
		return nil, errors.Errorf("Fail get auth info from session")
	}
	return ainfo, nil
}
