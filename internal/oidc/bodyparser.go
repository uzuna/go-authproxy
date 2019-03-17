package oidc

import (
	"net/http"

	"github.com/pkg/errors"
)

// AuthResponse is information of authenticate responce
type AuthResponse struct {
	IDToken string
	Code    string
	State   string
}

// ParseAuthResponse is Parsing Request
func ParseAuthResponse(r *http.Request) (*AuthResponse, error) {
	var err error
	// form_check

	// openid-connect-core-1.0: 3.1.2.5. | 3.1.2.6.
	contentType := r.Header.Get("Content-Type")
	if contentType != expectContentType {
		return nil, errors.Errorf("Invalid format type")
	}

	// Start parse
	err = r.ParseForm()
	if err != nil {
		return nil, errors.Wrapf(err, "[Request Error]Has not post body")
	}

	// When Authentication Error Response
	errorStr := r.Form.Get("error")
	if len(errorStr) > 0 {
		return nil, errors.Errorf("[Authentication Error: %s]%s", errorStr, r.Form.Get("error_description"))
	}

	// stateを確認
	state := r.Form.Get("state")
	if len(state) < 1 {
		return nil, errors.Errorf("[Request Error: Not foundstate]")
	}

	// IDTokenを確認
	idtokenStr := r.Form.Get("id_token")
	if len(idtokenStr) < 1 {
		return nil, errors.Errorf("[Request Error: Not found id_token]")
	}
	codeStr := r.Form.Get("code")

	return &AuthResponse{
		IDToken: idtokenStr,
		Code:    codeStr,
		State:   state,
	}, nil
}
