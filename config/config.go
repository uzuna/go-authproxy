package config

import (
	"fmt"
	"os"

	"golang.org/x/oauth2"
)

// Configure for OpenIDConnect id_token flow
type Config struct {
	ClientID        string `json:"client_id"`
	ClientSecret    string `json:"client_secret"`
	RedirectAddress string `json:"redirect_address"`
	AuthURL         string `json:"auth_url"`
	TokenURL        string `json:"token_url"`
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
