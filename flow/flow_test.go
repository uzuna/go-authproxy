package flow

import (
	"bytes"
	"context"
	"io"
	"log"
	"testing"

	"github.com/joho/godotenv"
)

func TestGetToken(t *testing.T) {
	godotenv.Load("../.env")
	c := LoadConfig()
	v, err := GetAccessToken(c)
	checkError(t, err)

	log.Printf("%#v", v.AccessToken)

	//
	o := GetOauthConfig(c)
	ctx := context.Background()
	cli := o.Client(ctx, v)

	// Check access
	res, err := cli.Get("https://graph.microsoft.com/oidc/userinfo")
	checkError(t, err)

	b := new(bytes.Buffer)
	_, err = io.Copy(b, res.Body)
	log.Printf(b.String(), err)
}

func checkError(t *testing.T, err error) {
	if err != nil {
		t.Log(err)
		t.Fail()
	}
}
