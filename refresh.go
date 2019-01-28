package authproxy

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"

	"github.com/gorilla/sessions"
)

const (
	StatusUnAuthorized        = iota // 認証情報なし
	StatusLoggedIn                   // Loggedin and active Access Token
	StatusAccessTokenUpdated         // Loggedin and active Access Token
	StatusAccessTokenExpired         // AccessToken期限切れ
	StatusRefreshTokenExpired        // RefreshToken期限切れ
)

var (
	CtxAuthStatus = &ContextKey{"auth_status"}
	CtxAuthDetail = &ContextKey{"auth_detail"}
)

// Refresh is chekc roken expire and refresh access token
func Refresh(oc *oauth2.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Sessionを取得
			ses, ok := r.Context().Value(CtxSession).(*sessions.Session)
			if !ok {
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxAuthStatus, StatusUnAuthorized)
				ctx = context.WithValue(ctx, CtxAuthDetail, "Not found session in context")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Tokenを確認
			idtokens, ok := ses.Values[SesKeyToken].(OpenIDToken)
			if !ok {
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxAuthStatus, StatusUnAuthorized)
				ctx = context.WithValue(ctx, CtxAuthDetail, "Not found id_token in session")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// AccessTokenが有効ならnext
			token := &idtokens
			timeout := time.Now().Sub(token.Expire)
			if timeout < 0 {
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxAuthStatus, StatusLoggedIn)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Refreshが有効期限内なら 更新する
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			ts := oc.TokenSource(ctx, idtokens.Token)
			tnew, err := ts.Token()
			if err != nil {
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxAuthStatus, StatusRefreshTokenExpired)
				ctx = context.WithValue(ctx, CtxAuthDetail, err.Error())
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// 更新出来たらSessionStoreを更新
			// @todo session idの更新はいつ行うか
			token.Expire = tnew.Expiry
			token.Token = tnew
			ses.Values[SesKeyToken] = token
			err = ses.Save(r, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			ctx = r.Context()
			ctx = context.WithValue(ctx, CtxAuthStatus, StatusAccessTokenUpdated)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		return http.HandlerFunc(fn)
	}
}
