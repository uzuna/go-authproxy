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

func (a *ContextAccess) ErrorRecord(r *http.Request) (*ErrorRecord, error) {
	detail, ok := r.Context().Value(CtxErrorRecord).(*ErrorRecord)
	if !ok {
		return nil, errors.Errorf("Has not ErrorRecord")
	}
	return detail, nil
}

type SessionAccess struct{}

func (a *SessionAccess) Token(ses *sessions.Session) (*OpenIDToken, error) {
	idtokens, ok := ses.Values[SesKeyToken].(*OpenIDToken)
	if !ok {
		return nil, errors.Errorf("Has not Auth Status")
	}
	return idtokens, nil
}

// func (a *SessionAccess) LoginReferer(ses *sessions.Session) (*OpenIDToken, error) {
// 	idtokens, ok := ses.Values[SesLoginReferer].(OpenIDToken)
// 	if !ok {
// 		return nil, errors.Errorf("Has not Auth Status")
// 	}
// 	return &idtokens, nil
// }
