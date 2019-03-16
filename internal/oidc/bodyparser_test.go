package oidc_test

import (
	"bytes"
	"io/ioutil"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uzuna/go-authproxy/internal/oidc"

	"github.com/pkg/errors"
)

func TestParseIDTokenBody(t *testing.T) {
	code := "SplxlOBeZQQYbYS6WxSbIA"
	state := "123456"
	b, err := ioutil.ReadFile("./testdata/idtoken_sample.txt")
	checkError(t, errors.WithStack(err))
	v := url.Values{}
	v.Set("id_token", string(b))
	v.Set("code", code)
	v.Set("state", state)

	rw := bytes.NewBufferString(v.Encode())

	req := httptest.NewRequest("POST", "/", rw)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	tb, err := oidc.ParseIDTokenBody(req)
	checkError(t, errors.WithStack(err))
	assert.Equal(t, tb.Token, string(b))
	assert.Equal(t, tb.State, state)
}
func TestParseIDTokenBodyFail(t *testing.T) {
	state := "123456"
	v := url.Values{}
	v.Set("error", "invalid_request")
	v.Set("error_description", "Unsupported response_type value")
	v.Set("state", state)

	rw := bytes.NewBufferString(v.Encode())

	req := httptest.NewRequest("POST", "/", rw)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	_, err := oidc.ParseIDTokenBody(req)
	// assert.Equal(t, tb, nil)
	assert.True(t, strings.Contains(err.Error(), "invalid_request"))
	assert.True(t, strings.Contains(err.Error(), "Unsupported response_type"), err.Error())

}
