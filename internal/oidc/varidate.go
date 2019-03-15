package oidc

import (
	"context"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/pkg/errors"
)

const (
	expectContentType = "application/x-www-form-urlencoded"
)

type RequestValidator interface {
	State(state string) bool
	Nonce(nonce string) bool
}

// Validate 認証レスポンスを解してTokenを得る
func Validate(oc *Config, jwtParser jwt.Keyfunc, r *http.Request, rv RequestValidator) (Token, error) {
	// form_check

	// openid-connect-core-1.0: 3.1.2.5. | 3.1.2.6.
	contentType := r.Header.Get("Content-Type")
	if contentType != expectContentType {
		return nil, errors.Errorf("Invalid format type")
	}

	// Start parse
	err := r.ParseForm()
	if err != nil {
		return nil, errors.Wrapf(err, "Has not post body")
	}

	// When Authentication Error Response
	errorStr := r.Form.Get("error")
	if len(errorStr) > 0 {
		return nil, errors.Errorf("[Authentication Error: %s]%s", errorStr, r.Form.Get("error_descriptions"))
	}

	// stateを確認
	if rv.State(r.Form.Get("state")) {
		return nil, errors.Errorf("[Validation Error: invalid state]")
	}

	// IDTokenを確認
	idtokenStr := r.Form.Get("id_token")
	if len(idtokenStr) < 1 {
		return nil, errors.Errorf("[Validation Error: Not found id_token]")
	}
	idToken, err := jwt.Parse(idtokenStr, jwtParser)
	if err != nil {
		return nil, errors.Wrapf(err, "[Validation Error: Fail crypto]")
	}

	claims := idToken.Claims.(jwt.MapClaims)
	// Check Nonce
	if claims["nonce"] == nil || rv.Nonce(claims["nonce"].(string)) {
		return nil, errors.Errorf("[Validation Error: invalid nonce]")
	}
	// Check ClientID
	if claims["aud"] == nil || claims["aud"] != oc.ClientID {
		return nil, errors.Errorf("[Validation Error: Unmatch ClientID]")
	}
	// Check Audience
	if claims["aud"] == nil || claims["client_id"] != oc.ClientID {
		return nil, errors.Errorf("[Validation Error: Unmatch ClientID]")
	}

	// Codeがある場合はAuthorization Code flowで確認
	codeStr := r.Form.Get("code")
	if len(codeStr) > 0 {
		ctx := r.Context()
		act, err := getRefreshToken(ctx, oc, codeStr)
		if err != nil {
			// return IDToken
			return nil, nil
		}
		// return Refreshable Token
		_ = act
	}

	// nonceを確認

	return nil, nil
}

type AuthzCodeToken struct {
	AccessToken  string
	RefreshToken string
	ExpireIn     time.Duration
	ExpireAt     time.Time
}

func getRefreshToken(ctx context.Context, oc *Config, code string) (*AuthzCodeToken, error) {
	// build request

	// request

	// parse responce

	return nil, nil
}
