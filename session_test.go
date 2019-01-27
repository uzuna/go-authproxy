package authproxy_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/jwk"
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
	ns := authproxy.NewNonceStore(time.Minute)

	res, err := http.Get(os.Getenv("OAUTH_KEYS_URL"))
	if err != nil {
		panic(err)
	}
	set, err := ParseKeys(res.Body)
	if err != nil {
		panic(err)
	}

	r := chi.NewRouter()

	// Enabled session
	r.Use(authproxy.Session(store, "demo"))

	//
	r.Method("POST", "/", authproxy.Authorize(set, oc, ns))
	r.MethodFunc("GET", "/user", func(w http.ResponseWriter, r *http.Request) {
		v := r.Context().Value(authproxy.CtxSession).(*sessions.Session)
		// log.Printf("%#v", v.Values["jwttoken"])

		if token, ok := v.Values[authproxy.SesKeyToken].(authproxy.OpenIDToken); ok {
			vt := &token
			log.Println(vt)
			log.Println(vt.Token.Expiry)
			w.Write([]byte(vt.Email))
			return
		}
		w.Write([]byte("You are not logined"))
		return
	})
	r.Method("GET", "/login", authproxy.Login(oc, ns))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		// v := r.Context().Value(authproxy.CtxSession).(*sessions.Session)
		w.Write([]byte("Accept"))
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
	t.SkipNow()
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

// parse json web key from io.Reader
func ParseKeys(r io.Reader) (*jwk.Set, error) {
	b := new(bytes.Buffer)
	_, err := io.Copy(b, r)
	if err != nil {
		return nil, err
	}
	return jwk.Parse(b.Bytes())
}
