package main

import (
	"context"
	"encoding/json"
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
	"github.com/gorilla/sessions"
	"github.com/quasoft/memstore"
	"github.com/uzuna/go-authproxy/oidc"
	"gopkg.in/yaml.v2"
)

var (
	sessionKeyState = "state" // Identity key of session
)

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
	server(a, store)
}

func panicError(err error) {
	if err != nil {
		panic(err)
	}
}

func server(a oidc.Authenticator, store sessions.Store) error {

	// 	// CustomErrorPages
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

	// mount session information
	r.Use(session.Session(store, "demo"))

	r.MethodFunc("POST", "/cb", func(w http.ResponseWriter, r *http.Request) {
		ares, err := a.Authenticate(r)
		if err != nil {
			ep.Error(w, r, err.Error(), 401)
			return
		}

		// Check session
		ses, err := session.GetSession(r)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}
		state, ok := ses.Values[sessionKeyState].(string)
		if !ok {
			err = errors.Errorf("Has not state in session")
			ep.Error(w, r, err.Error(), 503)
			return
		}
		if ares.State != state {
			err = errors.Errorf("Unmatch state")
			ep.Error(w, r, err.Error(), 401)
			return
		}

		// show
		enc := json.NewEncoder(w)
		err = enc.Encode(&ares)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}

	})
	r.MethodFunc("GET", "/login", func(w http.ResponseWriter, r *http.Request) {
		// Check session
		ses, err := session.GetSession(r)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}

		// generate URL
		state := oidc.GenState()
		authpath, err := a.AuthURL(state,
			oidc.SetURLParam("response_mode", "form_post"),
		)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}

		// save state this session
		ses.Values[sessionKeyState] = state
		err = ses.Save(r, w)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}
		w.Header().Set("Location", authpath)
		w.WriteHeader(http.StatusFound)
	})
	r.MethodFunc("GET", "/", func(w http.ResponseWriter, r *http.Request) {
		// Check session
		ses, err := session.GetSession(r)
		if err != nil {
			ep.Error(w, r, err.Error(), 503)
			return
		}

		log.Println(ses.Values)
		// show
		w.Write([]byte("Accept"))
	})

	// 	a := &authproxy.ContextAccess{}

	// 	r.Group(func(r chi.Router) {
	// 		r.Use(authproxy.Refresh(oc))
	// 		r.Use(rr)
	// 		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
	// 			ses, err := a.Session(r)
	// 			if err != nil {
	// 				http.Error(w, err.Error(), http.StatusUnauthorized)
	// 				return
	// 			}
	// 			er, err := a.ErrorRecord(r)

	// 			// if err != nil {
	// 			// 	http.Error(w, err.Error(), http.StatusUnauthorized)
	// 			// 	return
	// 			// }
	// 			switch er.Code {
	// 			// case authproxy.StatusUnAuthorized:
	// 			// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 			// 	doc := `
	// 			// 		<p>You are not authorized. <a href="/login">Prease Login</a></p>
	// 			// 	`
	// 			// 	w.Write([]byte(doc))
	// 			// case authproxy.StatusAccessTokenExpired:

	// 			// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 			// 	doc := `
	// 			// 		<p>Your Access Token Expired.</p>
	// 			// 	`
	// 			// 	w.Write([]byte(doc))
	// 			// case authproxy.StatusRefreshTokenExpired:

	// 			// 	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 			// 	doc := `
	// 			// 		<p>Your Refresh Token Expired. <a href="/login">Prease ReLogin</a></p>
	// 			// 	`
	// 			// 	w.Write([]byte(doc))
	// 			case authproxy.StatusLoggedIn, authproxy.StatusAccessTokenUpdated:
	// 				sa := &authproxy.SessionAccess{}
	// 				token, err := sa.Token(ses)
	// 				if err != nil {
	// 					http.Error(w, err.Error(), http.StatusInternalServerError)
	// 					return
	// 				}

	// 				w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 				doc := fmt.Sprintf(`<p>You are %s</p>`, token.Email)
	// 				w.Write([]byte(doc))
	// 			default:
	// 				w.Write([]byte("Not Login"))
	// 			}

	// 		})
	// 	})

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
