package authproxy

import (
	"context"
	"net/http"
	"time"

	"golang.org/x/oauth2"
)

const (
	errUnAuthorized        = iota // 認証情報なし
	errUndefinedRoute             // 内部ルーティングのミス
	errInvalidBody                // Authorize body is invalid
	errFailGetToken               // Can not get token by code
	errFailSession                // Session fail
	errLoggedIn                   // Loggedin and active Access Token
	errLogIn                      // 初回Login
	errAccessTokenUpdated         // Loggedin and active Access Token
	errAccessTokenExpired         // AccessToken期限切れ
	errRefreshTokenExpired        // RefreshToken期限切れ
)

type authResult struct {
	ErrCode int
	Message string
}

// Refresh is chekc roken expire and refresh access token
func Refresh(oc *oauth2.Config) func(http.Handler) http.Handler {
	cac := &ContextAccess{}
	sa := &SessionAccess{}
	return func(next http.Handler) http.Handler {

		errorBind := func(w http.ResponseWriter, r *http.Request, er *authResult) {
			ctx := r.Context()
			ctx = context.WithValue(ctx, CtxAuthResult, er)
			next.ServeHTTP(w, r.WithContext(ctx))
		}
		fn := func(w http.ResponseWriter, r *http.Request) {
			// Sessionを取得
			ses, err := cac.Session(r)
			if err != nil {
				er := &authResult{
					ErrCode: errFailSession,
					Message: "Not found session in context",
				}
				errorBind(w, r, er)
				return
			}

			// UserInfo check
			uinfo, err := sa.UserInfo(ses)
			if err != nil {
				er := &authResult{
					ErrCode: errFailSession,
					Message: "Not found userinfo in session",
				}
				errorBind(w, r, er)
				return
			}

			// AccessTokenが有効ならnext
			timeout := time.Now().Sub(uinfo.Expire)
			if timeout > 0 {
				er := &authResult{ErrCode: errLoggedIn}
				errorBind(w, r, er)
				return
			}

			// Refreshが有効期限内なら 更新する
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			defer cancel()
			ts := oc.TokenSource(ctx, uinfo.Token)
			tnew, err := ts.Token()
			if err != nil {
				er := &authResult{
					ErrCode: errRefreshTokenExpired,
					Message: err.Error(),
				}
				errorBind(w, r, er)
				return
			}
			// 更新出来たらSessionStoreを更新
			// @todo session idの更新はいつ行うか
			uinfo.Expire = tnew.Expiry
			uinfo.Token = tnew
			ses.Values[sesUserInfo] = uinfo
			err = ses.Save(r, w)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			ctx = r.Context()
			er := &authResult{ErrCode: errAccessTokenUpdated}
			ctx = context.WithValue(ctx, CtxAuthResult, er)
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
			er, err := cac.authResult(r)
			if err != nil {
				er := &ErrorRecord{
					StatusCode: http.StatusUnauthorized,
					Message:    "Unknown login status",
				}
				ctx = context.WithValue(ctx, CtxErrorRecord, er)
				epage.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			switch er.ErrCode {
			case errLoggedIn, errAccessTokenUpdated:
				// login済みのため次へ
				next.ServeHTTP(w, r)
				return
			case errLogIn:
				// Login初回
				// @todo Sessionに移動先候補があればそこに移動する
				next.ServeHTTP(w, r)
				return
			case errRefreshTokenExpired:
				// @todo 現在のアドレスを移動先として保持。再ログイン後に移動するため
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			case errInvalidBody:
				ctx = context.WithValue(ctx, CtxErrorRecord, &ErrorRecord{
					StatusCode: http.StatusBadRequest,
					Message:    er.Message,
				})
			case errFailGetToken, errFailSession:
				ctx = context.WithValue(ctx, CtxErrorRecord, &ErrorRecord{
					StatusCode: http.StatusInternalServerError,
					Message:    er.Message,
				})
			case errUnAuthorized:
				// @todo 現在のアドレスを移動先として保持。再ログイン後に移動するため
				ctx = context.WithValue(ctx, CtxErrorRecord, &ErrorRecord{
					StatusCode: http.StatusUnauthorized,
					Message:    er.Message,
				})
			default:
				ctx = context.WithValue(ctx, CtxErrorRecord, &ErrorRecord{
					StatusCode: http.StatusNotFound,
					Message:    er.Message,
				})
			}
			epage.ServeHTTP(w, r.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	}
}
