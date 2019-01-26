package authproxy

import (
	"context"
	"net/http"

	"github.com/gorilla/sessions"
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
