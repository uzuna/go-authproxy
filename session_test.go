package authproxy_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/quasoft/memstore"
	"github.com/skratchdot/open-golang/open"
	"github.com/stretchr/testify/assert"
	"github.com/uzuna/go-authproxy/config"

	"github.com/go-chi/chi"
	authproxy "github.com/uzuna/go-authproxy"

	"github.com/gorilla/sessions"
)

var store sessions.Store
var route chi.Router

func TestMain(m *testing.M) {

	store := memstore.NewMemStore(
		[]byte("authkey123"),
		[]byte("enckey12341234567890123456789012"),
	)

	godotenv.Load()
	c := config.LoadConfig()
	oc := config.GetOauthConfig(c)

	//jws
	res, err := http.Get(os.Getenv("OAUTH_KEYS_URL"))
	if err != nil {
		panic(err)
	}
	set, err := authproxy.ParseKeys(res.Body)
	if err != nil {
		panic(err)
	}
	az := authproxy.NewIDTokenValidator(
		set,
		strings.Split(os.Getenv("OAUTH_ISSUER"), ","),
		strings.Split(os.Getenv("OAUTH_AUDIENCE"), ","),
	)

	h, err := authproxy.NewAuthenticateHandlers(oc, az, store)
	if err != nil {
		panic(err)
	}

	r := chi.NewRouter()

	// Enabled session
	r.Use(h.Session())

	//
	ca := &authproxy.ContextAccess{}
	sa := &authproxy.SessionAccess{}
	ep, _ := authproxy.NewErrorPages()
	rh := authproxy.RerouteRedirect(ep, "/")
	r.Method("GET", "/login", h.LoginRedirect())
	r.MethodFunc("GET", "/404", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, authproxy.CtxHTTPStatus, http.StatusNotFound)
		ctx = context.WithValue(ctx, authproxy.CtxErrorRecord, &authproxy.ErrorRecord{
			Code:    http.StatusNotFound,
			Message: "You are accessed to \"not found.\"",
		})
		ep.ServeHTTP(w, r.WithContext(ctx))
	})
	r.Method("POST", "/", h.ValidateCredential()(rh))
	r.MethodFunc("GET", "/user", func(w http.ResponseWriter, r *http.Request) {
		ses, err := ca.Session(r)
		if err != nil {
			w.Write([]byte(err.Error()))
			return
		}
		uinfo, err := sa.UserInfo(ses)
		if err == nil {
			log.Println(uinfo.Expire)
			w.Header().Set("Content-Type", "text/html; charset=utf8")
			w.Write([]byte(uinfo.Email))
			w.Write([]byte(`DummyLink: <a href="/404"> 404 Page </a>`))
			return
		}
		w.Write([]byte(fmt.Sprintf("You are not logined %s", err.Error())))
		return
	})
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		// v := r.Context().Value(authproxy.CtxSession).(*sessions.Session)
		w.Header().Set("Content-Type", "text/html; charset=utf8")
		w.Write([]byte(`Accept: <a href="/user"> User Page </a>`))
		w.Write([]byte(`DummyLink: <a href="/404"> 404 Page </a>`))
	})
	route = r

	code := m.Run()
	os.Exit(code)
}

func TestSession(t *testing.T) {

	type RequestTest struct {
		Method  string
		Path    string
		CodeExp int
		Body    func(string) bool
	}

	table := []RequestTest{
		// {Method: "GET", Path: "/"},
		{Method: "GET", Path: "/login", CodeExp: 302, Body: func(b string) bool {
			return strings.Contains(b, "a href=")
		}},
		{Method: "POST", Path: "/", CodeExp: 400, Body: func(b string) bool {
			return strings.Contains(b, "Has not id_token")
		}},
	}

	for _, v := range table {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(v.Method, v.Path, nil)
		route.ServeHTTP(rec, req)

		assert.Equal(t, v.CodeExp, rec.Code)
		assert.True(t, v.Body(rec.Body.String()))
		// log.Println("Result", rec.HeaderMap)
	}
}

func TestAuthorizeFlow(t *testing.T) {
	// t.SkipNow()
	addr := os.Getenv("HTTP_ADDR")
	wait := make(chan struct{})
	// route.MethodFunc("GET", "/close", func(w http.ResponseWriter, r *http.Request) {
	// 	wait <- struct{}{}
	// })
	srv := &http.Server{Addr: addr, Handler: route}

	listenWait := make(chan struct{})
	go func() {
		listenWait <- struct{}{}
		if err := srv.ListenAndServe(); err != nil {
			log.Print(err)
		}
	}()

	// wait
	<-listenWait

	err := open.Start(fmt.Sprintf("http://%s/login", addr))
	if err != nil {
		t.Logf("%#v", err)
		t.Fail()
		return
	}

	// forever
	<-wait

	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	if err := srv.Shutdown(ctx); err != nil {
		log.Print(err)
	}

}
