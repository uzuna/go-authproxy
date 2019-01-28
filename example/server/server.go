package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/joho/godotenv"
	"github.com/quasoft/memstore"
	"github.com/uzuna/go-authproxy/config"

	"github.com/go-chi/chi"
	authproxy "github.com/uzuna/go-authproxy"

	"github.com/gorilla/sessions"
)

var store sessions.Store
var route chi.Router

func main() {

	store := memstore.NewMemStore(
		[]byte("authkey123"),
		[]byte("enckey12341234567890123456789012"),
	)

	godotenv.Load()
	c := config.LoadConfig()
	oc := config.GetOauthConfig(c)
	ns := authproxy.NewNonceStore(time.Minute)

	res, err := http.Get(os.Getenv("OAUTH_KEYS_URL"))
	if err != nil {
		panic(err)
	}
	set, err := authproxy.ParseKeys(res.Body)
	if err != nil {
		panic(err)
	}

	r := chi.NewRouter()
	r.Use(authproxy.Session(store, "demo"))

	r.Method("POST", "/", authproxy.Authorize(set, oc, ns))
	r.Method("GET", "/login", authproxy.Login(oc, ns))

	a := &authproxy.ContextAccess{}

	r.Group(func(r chi.Router) {
		r.Use(authproxy.Refresh(oc))
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			ses, err := a.Session(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			status, err := a.AuthStatus(r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			switch status {
			case authproxy.StatusUnAuthorized:
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				doc := `
					<p>You are not authorized. <a href="/login">Prease Login</a></p>
				`
				w.Write([]byte(doc))
			case authproxy.StatusAccessTokenExpired:

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				doc := `
					<p>Your Access Token Expired.</p>
				`
				w.Write([]byte(doc))
			case authproxy.StatusRefreshTokenExpired:

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				doc := `
					<p>Your Refresh Token Expired. <a href="/login">Prease ReLogin</a></p>
				`
				w.Write([]byte(doc))
			case authproxy.StatusLoggedIn, authproxy.StatusAccessTokenUpdated:
				sa := &authproxy.SessionAccess{}
				token, err := sa.Token(ses)
				if err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}

				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				doc := fmt.Sprintf(`<p>You are %s</p>`, token.Email)
				w.Write([]byte(doc))
			}

		})
	})

	addr := os.Getenv("HTTP_ADDR")
	srv := &http.Server{Addr: addr, Handler: r}
	go func() {
		log.Println(fmt.Sprintf("Listen %s", addr))
		if err := srv.ListenAndServe(); err != nil {
			log.Print(err)
		}
	}()

	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt)
	<-ch
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	srv.Shutdown(ctx)

}
