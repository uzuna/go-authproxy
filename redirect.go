package authproxy

import (
	"context"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
)

type RedirectConfig struct {
	Oauth2Config      *oauth2.Config
	LoginPass         string
	RefreshLowerLimit time.Duration
}

// LoginRedirect is switch proxy or redirect to login
func LoginRedirect(conf *RedirectConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {

			ses, ok := r.Context().Value(CtxSession).(*sessions.Session)
			if !ok {
				err := errors.Errorf("Not found session data")
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			redirectFunc := func() {
				ses.Values[sesAuthRefere] = r.URL.String()
				err := ses.Save(r, w)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
				http.Redirect(w, r, conf.LoginPass, 302)
			}
			idtokens, ok := ses.Values[SesKeyToken].(OpenIDToken)
			if !ok {
				redirectFunc()
				return
			}
			// AccessTokenが有効ならnext
			token := &idtokens
			timeout := time.Now().Sub(token.Expire)
			if timeout > time.Minute*5 {
				next.ServeHTTP(w, r)
				return
			} else if timeout > 0 {
				// Refreshが有効期限内なら 更新して返す
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
				defer cancel()
				ts := conf.Oauth2Config.TokenSource(ctx, idtokens.Token)
				tnew, err := ts.Token()
				if err != nil {
					// 更新出来ない場合はLogin Redirect
					// それともUnAutorizedを返すのが良い?
					redirectFunc()
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
				next.ServeHTTP(w, r)
				return
			}
			// @todo Access Token期限切れは同様の接続すべてを一時的に止めてTokenを更新する
			http.Error(w, "Token Expired", http.StatusUnauthorized)
			return
		}
		return http.HandlerFunc(fn)
	}
}
