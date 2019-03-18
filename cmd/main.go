package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"syscall"

	"github.com/go-chi/chi"
	"github.com/gorilla/sessions"
	"github.com/pkg/errors"
	"github.com/quasoft/memstore"
	"github.com/sirupsen/logrus"
	"github.com/uzuna/go-authproxy/errorpage"
	"github.com/uzuna/go-authproxy/internal/session"
	"github.com/uzuna/go-authproxy/oidc"
	"github.com/uzuna/go-authproxy/router"
	"gopkg.in/yaml.v2"
)

func main() {

	// initialize
	conf, err := loadConfig()
	panicError(err)

	// build router
	r, err := buildRouter(conf)
	panicError(err)

	// start server
	addr := fmt.Sprintf(":%d", conf.Port)
	srv := &http.Server{Addr: addr, Handler: r}
	go func() {
		logrus.Infof("Start Listen: %s", addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Print(err)
		}
	}()

	// listen signal
	sigCh := WaitSignal()
outloop:
	for {
		sig := <-sigCh
		switch sig {
		case syscall.SIGHUP:
			log.Println("Signal Hungup")
		default:
			logrus.Infof("Signal: %s", sig.String())
			break outloop
		}
	}
	// close server
}

// locaf config and initialize structs
func buildRouter(conf *Config) (http.Handler, error) {
	// load config
	f, err := os.Open(conf.AuthConfigFile)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	dec := yaml.NewDecoder(f)
	var oidcconf oidc.Config
	err = dec.Decode(&oidcconf)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Init session
	store := memstore.NewMemStore(
		[]byte("authkey123"),
		[]byte("enckey12341234567890123456789012"),
	)

	// Init CustomErrorPages
	ep, err := errorpage.NewErrorPages()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return server(conf, oidcconf, store, ep)
}

// build http router
func server(conf *Config,
	oidcconf oidc.Config,
	store sessions.Store,
	ep *errorpage.ErrorPages) (http.Handler, error) {

	// session名
	sessionName := conf.SessionName
	aikey := &contextKey{"authinfo"}

	// OIDC RouterProvider
	auth, err := oidc.NewAuthenticator(&oidcconf)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	aStore := session.NewAuthStore(store, sessionName, aikey)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	rp := router.New(auth, aStore, ep, aikey)

	// ReverseProxy
	u, err := url.Parse(conf.ForwardTo)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	list := []router.AdditionalHeader{
		{"preferred_username", "X-Username"},
	}
	rph := rp.ReverseProxy(u, list)

	// mux
	r := chi.NewRouter()

	// Set default not found page
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

	// Route of Login Redirect
	// This generates and to redierct to AuthURL for OIDC login
	reRef := regexp.MustCompile(conf.AcceptOriginPtn)
	erp := router.ReferrerMatch(reRef)
	r.Method("GET", "/login", rp.Login(erp))

	// Accept Public files
	r.Route("/public", func(r chi.Router) {
		r.Handle("/*", rph)
	})

	// other route must login
	r.Route("/", func(r chi.Router) {
		r.Use(rp.AuthRedirect())
		r.Handle("/*", rph)
	})
	return r, nil
}

func panicError(err error) {
	if err != nil {
		panic(err)
	}
}

type contextKey struct {
	Name string
}
