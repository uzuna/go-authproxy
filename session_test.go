package authproxy_test

import (
	"bytes"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/uzuna/go-authproxy/config"

	"github.com/go-chi/chi"
	authproxy "github.com/uzuna/go-authproxy"

	"github.com/gorilla/sessions"
)

var store sessions.Store
var route chi.Router

func TestMain(m *testing.M) {
	store = sessions.NewCookieStore([]byte("test"))

	godotenv.Load()
	c := config.LoadConfig()
	oc := config.GetOauthConfig(c)
	ns := authproxy.NewNonceStore()

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
	r.Method("GET", "/login", authproxy.Redirect(oc, ns))
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		v := r.Context().Value(authproxy.CtxSession).(*sessions.Session)
		log.Println("sessions", v.Values)
		w.Write([]byte("Accespt"))
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

// parse json web key from io.Reader
func ParseKeys(r io.Reader) (*jwk.Set, error) {
	b := new(bytes.Buffer)
	_, err := io.Copy(b, r)
	if err != nil {
		return nil, err
	}
	return jwk.Parse(b.Bytes())
}
