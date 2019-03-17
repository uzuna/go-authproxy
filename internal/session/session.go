package session

import (
	"context"
	"net/http"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
)

var (
	CtxSession = &ContextKey{"Session"} // Identity key of session
)

type ContextKey struct {
	Name string
}

// Session generates http middlerware handler for session generate and assing to context
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

func GetSession(r *http.Request) (*sessions.Session, error) {
	ses, ok := r.Context().Value(CtxSession).(*sessions.Session)
	if !ok {
		return nil, errors.Errorf("Has not session in context")
	}
	return ses, nil
}
