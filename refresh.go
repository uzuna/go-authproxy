package authproxy

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const (
	StatusUnAuthorized        = iota // 認証情報なし
	StatusUndefinedRoute             // 内部ルーティングのミス
	StatusInvalidBody                // Authorize body is invalid
	StatusFailGetToken               // Can not get token by code
	StatusFailSession                // Session fail
	StatusLoggedIn                   // Loggedin and active Access Token
	StatusLogIn                      // 初回Login
	StatusAccessTokenUpdated         // Loggedin and active Access Token
	StatusAccessTokenExpired         // AccessToken期限切れ
	StatusRefreshTokenExpired        // RefreshToken期限切れ
)

var (
	CtxErrorRecord = &ContextKey{"error_record"}
	CtxHTTPStatus  = &ContextKey{"http_status_code"}
)

// Refresh is chekc roken expire and refresh access token
func Refresh(oc *oauth2.Config) func(http.Handler) http.Handler {
	cac := &ContextAccess{}
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Sessionを取得
			ses, err := cac.Session(r)
			if err != nil {
				er := &ErrorRecord{
					Code:    StatusUnAuthorized,
					Message: "Not found session in context",
				}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Tokenを確認
			idtokens, ok := ses.Values[SesKeyToken].(OpenIDToken)
			if !ok {
				er := &ErrorRecord{
					Code:    StatusUnAuthorized,
					Message: "Not found id_token in session",
				}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
			// AccessTokenが有効ならnext
			token := &idtokens
			timeout := time.Now().Sub(token.Expire)
			if timeout > 0 {
				er := &ErrorRecord{Code: StatusLoggedIn}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// Refreshが有効期限内なら 更新する
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			ts := oc.TokenSource(ctx, idtokens.Token)
			tnew, err := ts.Token()
			if err != nil {
				er := &ErrorRecord{
					Code:    StatusRefreshTokenExpired,
					Message: err.Error(),
				}
				ctx := r.Context()
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
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
				return
			}
			ctx = r.Context()
			er := &ErrorRecord{Code: StatusAccessTokenUpdated}
			ctx = context.WithValue(ctx, CtxErrorRecord, er)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		return http.HandlerFunc(fn)
	}
}

// for Autorize Handler
func RerouteRedirect(epage *ErrorPages, path string) http.Handler {
	rh := Reroute(epage)
	fn := func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, path, http.StatusFound)
	}
	return rh(http.HandlerFunc(fn))
}

// Check Loginstatus and re-routing request
func Reroute(epage *ErrorPages) func(http.Handler) http.Handler {
	cac := &ContextAccess{}
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			er, err := cac.ErrorRecord(r)
			if err != nil {
				er = &ErrorRecord{
					Code:    StatusUnAuthorized,
					Message: "Unknown login status",
				}
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				ctx = context.WithValue(ctx, CtxHTTPStatus, http.StatusInternalServerError)
				epage.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			switch er.Code {
			case StatusLoggedIn, StatusAccessTokenUpdated:
				// login済みのため次へ
				next.ServeHTTP(w, r)
				return
			case StatusLogIn:
				// Login初回
				// @todo Sessionに移動先候補があればそこに移動する
				next.ServeHTTP(w, r)
				return
			case StatusRefreshTokenExpired:
				// @todo 現在のアドレスを移動先として保持。再ログイン後に移動するため
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			case StatusInvalidBody:
				ctx = context.WithValue(ctx, CtxHTTPStatus, http.StatusBadRequest)
			case StatusFailGetToken, StatusFailSession:
				ctx = context.WithValue(ctx, CtxHTTPStatus, http.StatusInternalServerError)
			case StatusUnAuthorized:
				// @todo 現在のアドレスを移動先として保持。再ログイン後に移動するため
				ctx = context.WithValue(ctx, CtxHTTPStatus, http.StatusUnauthorized)
			default:
				ctx = context.WithValue(ctx, CtxHTTPStatus, http.StatusNotFound)
			}
			epage.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
