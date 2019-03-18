package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"regexp"
	"time"

	"github.com/uzuna/go-authproxy/errorpage"
	"github.com/uzuna/go-authproxy/internal/session"
	"github.com/uzuna/go-authproxy/router"

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

	// CustomErrorPages
	ep, err := errorpage.NewErrorPages()
	panicError(err)
	rp := router.New(a, as, ep, aikey)
	server(rp, ep, aikey)
}

func panicError(err error) {
	if err != nil {
		panic(err)
	}
}

func server(rp router.RouteProvider, ep *errorpage.ErrorPages, aikey interface{}) error {

	// Proxy to other server
	director := func(r *http.Request) {
		r.URL.Scheme = "http"
		r.URL.Host = "localhost:8080"

		// Check authinfo
		ainfo, err := rp.AuthInfo(r)
		if err != nil {
			return
		}
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", ainfo.IDToken))
		r.Header.Set("Forwerded", "localhost:8989")
	}
	rvh := &httputil.ReverseProxy{Director: director}

	// mux
	r := chi.NewRouter()

	// Setr defaul t not found page
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		s := fmt.Sprintf("Not found path: [%s]", r.URL.Path)
		ep.Error(w, r, s, 404)
	})

	// mount session information
	r.Use(rp.LoadSession())

	// Route of Authenticate CallBack
	// Parse Authenticate response
	// and authinfo to set to session store
	r.Method("POST", "/cb", rp.Authenticate())

	reRef := regexp.MustCompile(`^https?\:\/{2}localhost:8989\/.+$`)
	erp := router.ReferrerMatch(reRef)
	// Route of Login Redirect
	// This generates and to redierct to AuthURL for OIDC login
	r.Method("GET", "/login", rp.Login(erp))

	// Route of Top page
	r.MethodFunc("GET", "/", func(w http.ResponseWriter, r *http.Request) {
		// Check authinfo
		ainfo, err := rp.AuthInfo(r)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}

		// show
		w.Header().Set("Content-Type", "text/html")
		diff := ainfo.ExpireAt.Sub(time.Now())
		fmt.Fprintf(w, "<a href=\"/login\">Login</a>")
		fmt.Fprintf(w, "<p>Accept. LoggedIn: %v, Expires: %s ,ExpireAt: %s</p>", ainfo.LoggedIn, diff.String(), ainfo.ExpireAt.String())
	})

	r.Route("/withauth", func(r chi.Router) {
		r.Use(rp.AuthRedirect())
		r.Handle("/*", rvh)
	})
	r.Handle("/proxy/*", rvh)

	// Listen Proxy Server
	s1addr := ":8989"
	srv := &http.Server{Addr: s1addr, Handler: r}
	go func() {
		log.Println(fmt.Sprintf("Listen %s", s1addr))
		if err := srv.ListenAndServe(); err != nil {
			log.Print(err)
		}
	}()

	// Listen Echo Server
	recho := chi.NewRouter()
	recho.MethodFunc("GET", "/*", func(w http.ResponseWriter, r *http.Request) {
		// Check Header
		bearer := r.Header.Get("Authorization")
		forw := r.Header.Get("Forwerded")
		// show
		// w.Header().Set("Content-Type", "text/html")
		// diff := ainfo.ExpireAt.Sub(time.Now())
		// fmt.Fprintf(w, "<a href=\"/login\">Login</a>")
		// fmt.Fprintf(w, "<p>Wellcome to [%s]. LoggedIn: %v, Expires: %s ,ExpireAt: %s</p>", r.URL.Path, ainfo.LoggedIn, diff.String(), ainfo.ExpireAt.String())
		w.Write([]byte(bearer))
		w.Write([]byte(forw))
	})
	s2addr := ":8080"
	srv2 := &http.Server{Addr: s2addr, Handler: recho}
	go func() {
		log.Println(fmt.Sprintf("Listen %s", s2addr))
		if err := srv2.ListenAndServe(); err != nil {
			log.Print(err)
		}
	}()

	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt)
	<-ch
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	srv.Shutdown(ctx)
	srv2.Shutdown(ctx)
	return nil
}
