package authproxy

import (
	"context"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

var (
	CtxSession     = &ContextKey{"Session"}
	CtxAccessToken = &ContextKey{"AccessToken"}
)

type ContextKey struct {
	Name string
}

func Session(store sessions.Store, sessionName string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Get a session.
			session, err := store.Get(r, sessionName)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ctx := r.Context()
			ctx = context.WithValue(ctx, CtxSession, session)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}

type ContextAccess struct{}

func (a *ContextAccess) Session(r *http.Request) (*sessions.Session, error) {
	ses, ok := r.Context().Value(CtxSession).(*sessions.Session)
	if !ok {
		return nil, errors.Errorf("Has not session in context")
	}
	return ses, nil
}

func (a *ContextAccess) AuthStatus(r *http.Request) (int, error) {
	state, ok := r.Context().Value(CtxAuthStatus).(int)
	if !ok {
		return 0, errors.Errorf("Has not Auth Status")
	}
	return state, nil
}
func (a *ContextAccess) AuthDetail(r *http.Request) (string, error) {
	detail, ok := r.Context().Value(CtxAuthDetail).(string)
	if !ok {
		return "", errors.Errorf("Has not Auth Detail")
	}
	return detail, nil
}

type SessionAccess struct{}

func (a *SessionAccess) Token(ses *sessions.Session) (*OpenIDToken, error) {
	idtokens, ok := ses.Values[SesKeyToken].(OpenIDToken)
	if !ok {
		return nil, errors.Errorf("Has not Auth Status")
	}
	return &idtokens, nil
}
