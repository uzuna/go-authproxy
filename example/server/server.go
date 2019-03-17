package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/pkg/errors"
	"github.com/uzuna/go-authproxy/errorpage"
	"github.com/uzuna/go-authproxy/internal/session"

	"github.com/go-chi/chi"
	"github.com/quasoft/memstore"
	"github.com/uzuna/go-authproxy/oidc"
	"gopkg.in/yaml.v2"
)

var (
	sessionKeyState = "state" // Identity key of session
)

type contextKey struct {
	Name string
}

func main() {

	store := memstore.NewMemStore(
		[]byte("authkey123"),
		[]byte("enckey12341234567890123456789012"),
	)
	_ = store
	var oidcconf oidc.Config
	f, err := os.Open("./config.yml")
	panicError(err)
	dec := yaml.NewDecoder(f)
	err = dec.Decode(&oidcconf)
	panicError(err)
	a, err := oidc.NewAuthenticator(&oidcconf)
	panicError(err)

	sessionName := "demo"
	aikey := &contextKey{"authinfo"}
	as := session.NewAuthStore(store, sessionName, aikey)
	server(a, as, aikey)
}

func panicError(err error) {
	if err != nil {
		panic(err)
	}
}

func server(a oidc.Authenticator, as session.AuthStore, aiKey interface{}) error {

	// CustomErrorPages
	ep, err := errorpage.NewErrorPages()
	if err != nil {
		return errors.WithStack(err)
	}
	// 	rh := authproxy.RerouteRedirect(ep, "/")
	// 	rr := authproxy.Reroute(ep)
	// 	authMw := authproxy.Authorize(set, oc, ns)
	// 	authHandler := authMw(rh)

	// mux
	r := chi.NewRouter()

	// Setr defaul t not found page
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		s := fmt.Sprintf("Not found path: [%s]", r.URL.Path)
		ep.Error(w, r, s, 404)
	})

	// mount session information
	r.Use(as.Handler())

	// Route of Authenticate CallBack
	// Parse Authenticate response
	// and authinfo to set to session store
	r.MethodFunc("POST", "/cb", func(w http.ResponseWriter, r *http.Request) {
		ares, err := a.Authenticate(r)
		if err != nil {
			ep.Error(w, r, err.Error(), 401)
			return
		}

		ainfo, ok := r.Context().Value(aiKey).(*session.AuthInfo)
		if !ok {
			ep.Error(w, r, "Fail get session data", 503)
			return
		}

		if ares.State != ainfo.AuthenticationState {
			err = errors.Errorf("Unmatch state")
			ep.Error(w, r, err.Error(), 401)
			return
		}
		ainfo.AuthenticationState = ""
		ainfo.IDToken = ares.IDToken
		ainfo.ExpireAt = ares.Claims.Expire()
		ainfo.LoggedIn = true

		err = as.Save(w, r, ainfo)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}

		// Return to Top
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusSeeOther)
	})

	// Route of Login Redirect
	// This generates and to redierct to AuthURL for OIDC login
	r.MethodFunc("GET", "/login", func(w http.ResponseWriter, r *http.Request) {
		// Check authinfo
		ainfo, ok := r.Context().Value(aiKey).(*session.AuthInfo)
		if !ok {
			ep.Error(w, r, "Fail get session data", 503)
			return
		}
		// I lggedin and not expired return home
		if ainfo.LoggedIn && time.Since(ainfo.ExpireAt) < time.Duration(0) {
			w.Header().Set("Location", "/")
			w.WriteHeader(http.StatusSeeOther)
			return
		}

		// generate URL
		state := oidc.GenState()
		ainfo.AuthenticationState = state
		authpath, err := a.AuthURL(state,
			oidc.SetURLParam("response_mode", "form_post"),
		)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}
		err = as.Save(w, r, ainfo)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}

		w.Header().Set("Location", authpath)
		w.WriteHeader(http.StatusFound)
	})

	// Route of Top page
	r.MethodFunc("GET", "/", func(w http.ResponseWriter, r *http.Request) {
		// Check authinfo
		ainfo, ok := r.Context().Value(aiKey).(*session.AuthInfo)
		if !ok {
			ep.Error(w, r, "Fail get session data", 503)
			return
		}

		// show

		w.Header().Set("Content-Type", "text/html")
		diff := ainfo.ExpireAt.Sub(time.Now())
		fmt.Fprintf(w, "<a href=\"/login\">Login</a>")
		fmt.Fprintf(w, "<p>Accept. LoggedIn: %v, Expires: %s ,ExpireAt: %s</p>", ainfo.LoggedIn, diff.String(), ainfo.ExpireAt.String())
	})

	// Listen Server
	addr := os.Getenv("HTTP_ADDR")
	if len(addr) < 1 {
		addr = ":8989"
	}
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
	return nil
}
