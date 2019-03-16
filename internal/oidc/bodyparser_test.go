package oidc_test

import (
	"bytes"
	"io/ioutil"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/uzuna/go-authproxy/internal/oidc"

	"github.com/pkg/errors"
)

func TestParseIDTokenBody(t *testing.T) {
	state := "123456"
	b, err := ioutil.ReadFile("./testdata/idtoken_sample.txt")
	checkError(t, errors.WithStack(err))
	v := url.Values{}
	v.Set("id_token", string(b))
	v.Set("state", state)

	rw := bytes.NewBufferString(v.Encode())

	req := httptest.NewRequest("POST", "/", rw)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	checkError(t, errors.WithStack(err))
	tb, err := oidc.ParseIDTokenBody(req)
	checkError(t, errors.WithStack(err))
	assert.Equal(t, tb.Token, string(b))
	assert.Equal(t, tb.State, state)
}
