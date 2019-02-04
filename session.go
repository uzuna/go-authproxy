package authproxy

import (
	"context"
	"encoding/gob"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

const (
	sesState        = "state"
	SesLoginReferer = "login_referer"
	sesUserInfo     = "userinfo"
)

var (
	CtxSession     = &ContextKey{"Session"}      // Identity key of Session in Context
	CtxAuthResult  = &ContextKey{"auth_result"}  //
	CtxErrorRecord = &ContextKey{"error_record"} //
	CtxHTTPStatus  = &ContextKey{"http_status_code"}
)

type ContextKey struct {
	Name string
}

// Sessinoとユーザーを結び付ける情報
type UserSessionInfo struct {
	Token  *oauth2.Token
	Expire time.Time
	Email  string
}

func init() {
	gob.Register(UserSessionInfo{})
	gob.Register(oauth2.Token{})
}

// Session is generate http middlerware handler for session generate and assing to context
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

// ContextAccess is wrapper for access Context data
type ContextAccess struct{}

func (a *ContextAccess) Session(r *http.Request) (*sessions.Session, error) {
	ses, ok := r.Context().Value(CtxSession).(*sessions.Session)
	if !ok {
		return nil, errors.Errorf("Has not session in context")
	}
	return ses, nil
}

func (a *ContextAccess) authResult(r *http.Request) (*authResult, error) {
	result, ok := r.Context().Value(CtxAuthResult).(*authResult)
	if !ok {
		return nil, errors.Errorf("Has not ErrorRecord")
	}
	return result, nil
}

func (a *ContextAccess) ErrorRecord(r *http.Request) (*ErrorRecord, error) {
	detail, ok := r.Context().Value(CtxErrorRecord).(*ErrorRecord)
	if !ok {
		return nil, errors.Errorf("Has not ErrorRecord")
	}
	return detail, nil
}

type SessionAccess struct{}

func (a *SessionAccess) UserInfo(ses *sessions.Session) (*UserSessionInfo, error) {
	uinfo, ok := ses.Values[sesUserInfo].(UserSessionInfo)
	if !ok {
		return nil, errors.Errorf("Has not Auth Status")
	}
	return &uinfo, nil
}

// func (a *SessionAccess) LoginReferer(ses *sessions.Session) (*OpenIDToken, error) {
// 	idtokens, ok := ses.Values[SesLoginReferer].(OpenIDToken)
// 	if !ok {
// 		return nil, errors.Errorf("Has not Auth Status")
// 	}
// 	return &idtokens, nil
// }
