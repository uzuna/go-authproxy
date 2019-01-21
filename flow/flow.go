package flow

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/skratchdot/open-golang/open"
	"golang.org/x/oauth2"
)

// Configure for OpenIDConnect id_token flow
type Config struct {
	ClientID        string
	ClientSecret    string
	RedirectAddress string
	AuthURL         string
	TokenURL        string
}

func LoadConfig() *Config {
	config := Config{
		ClientID:        os.Getenv("CLIENT_ID"),
		ClientSecret:    os.Getenv("CLIENT_SECRET"),
		RedirectAddress: os.Getenv("REDIRECT_ADDR"),
		AuthURL:         os.Getenv("OAUTH_AUTH_URL"),
		TokenURL:        os.Getenv("OAUTH_TOKEN_URL"),
	}
	return &config
}
func GetOauthConfig(config *Config) *oauth2.Config {

	oauthConfig := &oauth2.Config{
		Scopes: []string{
			"openid",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthURL,
			TokenURL: config.TokenURL,
		},
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		RedirectURL:  fmt.Sprintf("http://%s", config.RedirectAddress),
	}
	return oauthConfig
}

func SelfClose(config *Config) error {

	// start listener
	l, err := net.Listen("tcp", config.RedirectAddress)
	if err != nil {
		return err
	}
	defer l.Close()

	quit := make(chan struct{})
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte(`<script>window.open("","_parent","").close()</script>`))
		w.(http.Flusher).Flush()
		notifier := w.(http.CloseNotifier)
		<-notifier.CloseNotify()
		quit <- struct{}{}
	}))
	adrs := fmt.Sprintf("http://%s", config.RedirectAddress)
	err = open.Start(adrs)
	<-quit

	return nil
}

// Get Access Token
func GetAccessToken(config *Config) (token *oauth2.Token, seqErr error) {
	// precheck
	if len(config.AuthURL) < 1 {
		return nil, errors.Errorf("Must set AuthURL [env:OAUTH_AUTH_URL]")
	}
	if len(config.TokenURL) < 1 {
		return nil, errors.Errorf("Must set TokenURL [env:OAUTH_TOKEN_URL]")
	}

	// start listener
	l, err := net.Listen("tcp", config.RedirectAddress)
	if err != nil {
		return nil, err
	}
	defer l.Close()

	stateBytes := make([]byte, 16)
	_, err = rand.Read(stateBytes)
	if err != nil {
		return nil, err
	}

	oauthConfig := GetOauthConfig(config)

	c := 40
	b := make([]byte, c)
	rand.Read(b)
	codeChallenge := base64.URLEncoding.EncodeToString(b)
	state := fmt.Sprintf("%x", stateBytes)
	adrs := oauthConfig.AuthCodeURL(state,
		oauth2.SetAuthURLParam("scope", "openid offline_access"),
		oauth2.SetAuthURLParam("response_mode", "form_post"),
		oauth2.SetAuthURLParam("response_type", "id_token code"),
		oauth2.SetAuthURLParam("nonce", "0011223"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
	)
	err = open.Start(adrs)
	if err != nil {
		return nil, err
	}

	var id_token, code string
	quit := make(chan struct{})
	go http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/" {
			err := req.ParseForm()
			if err != nil {
				seqErr = err
			} else {
				id_token = req.Form.Get("id_token")
				code = req.Form.Get("code")
				log.Println(req.Form)
			}
			// @todo how to close this windows?
			w.Write([]byte(`<script>window.open("about:blank","_self").close()</script>`))
			w.(http.Flusher).Flush()
			notifier := w.(http.CloseNotifier)
			<-notifier.CloseNotify()
			quit <- struct{}{}
		}
	}))
	<-quit
	_ = id_token

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	token, err = oauthConfig.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeChallenge),
	)
	return token, err
}
