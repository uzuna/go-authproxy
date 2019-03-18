package session

import (
	"context"
	"encoding/gob"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

var (
	// Identity key of auth info
	skAuthInfo = "authinfo"
)

func init() {
	gob.Register(AuthInfo{})
}

type sessionKey string

// AuthInfo is data type of authorization ingo
type AuthInfo struct {
	LoggedIn            bool      // Login済みか否か
	AuthenticationState string    // Authenticate時のstate
	LoginReferer        string    // Login前にアクセスしていたページ
	ExpireAt            time.Time // 現在のトークン有効期限
	IDToken             string    // IDToken
}

// NewAuthStore make AutuStore
func NewAuthStore(store sessions.Store, sessionName string, contextKey interface{}) AuthStore {
	return &authStore{
		store:       store,
		sessionName: sessionName,
		contextKey:  contextKey,
	}
}

// AuthStore deals Authorication information between implement
// and session store
type AuthStore interface {
	Handler() func(next http.Handler) http.Handler
	Save(w http.ResponseWriter, r *http.Request, info *AuthInfo) error
}

type authStore struct {
	store       sessions.Store
	sessionName string
	contextKey  interface{}
}

// Handler generates http middlerware handler for session generate and assing to context
func (a *authStore) Handler() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Get a session.
			ses, err := a.store.Get(r, a.sessionName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			var ai AuthInfo
			x, ok := ses.Values[skAuthInfo].(AuthInfo)
			if ok {
				ai = x
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, a.contextKey, &ai)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

// Handler generates http middlerware handler for session generate and assing to context
func (a *authStore) Save(w http.ResponseWriter, r *http.Request, info *AuthInfo) error {
	ses, err := a.store.Get(r, a.sessionName)
	if err != nil {
		return errors.WithStack(err)
	}
	ses.Values[skAuthInfo] = *info
	err = ses.Save(r, w)
	return errors.WithStack(err)
}
