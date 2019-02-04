package authproxy

import (
	"bytes"
	"io"
	"net/http"
	"text/template"

	"github.com/uzuna/go-authproxy/bindata"
)

// ErrorHandlerFunc is implementation of ErrorPage Renderer
type ErrorHandlerFunc func(w http.ResponseWriter, r *http.Request, e *ErrorRecord)

// ErrorRecord is body of Error record on Autenticate Process
type ErrorRecord struct {
	StatusCode int
	Message    string
}

// NewErrorPages create instance of ErrorPages
func NewErrorPages() (*ErrorPages, error) {
	erp := &ErrorPages{
		Map: make(map[int]ErrorHandlerFunc),
	}
	f, err := bindata.Assets.Open("/assets/html/error.html.tpl")
	if err != nil {
		return erp, err
	}
	defer f.Close()
	b := new(bytes.Buffer)
	io.Copy(b, f)
	tpl, err := template.New("error.html.tpl").Parse(b.String())
	if err != nil {
		return erp, err
	}
	erp.DefaultHandlerFunc(func(w http.ResponseWriter, r *http.Request, er *ErrorRecord) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(er.StatusCode)
		tpl.Execute(w, er)
	})

	return erp, nil
}

// ErrorPages is serve Custom Error page
type ErrorPages struct {
	Map                map[int]ErrorHandlerFunc
	defaultHandlerFunc ErrorHandlerFunc
}

// Static register static page to match http status code.
func (e *ErrorPages) Static(code int, doc string) {
	e.Map[code] = func(w http.ResponseWriter, r *http.Request, e *ErrorRecord) {
		w.WriteHeader(code)
		w.Write([]byte(doc))
	}
}

func (e *ErrorPages) ErrorHandlerFunc(code int, f ErrorHandlerFunc) {
	e.Map[code] = f
}

func (e *ErrorPages) Error(w http.ResponseWriter, r *http.Request, err string, code int) {
	e.Map[code](w, r, &ErrorRecord{StatusCode: code, Message: err})
}

func (e *ErrorPages) DefaultHandlerFunc(f ErrorHandlerFunc) {
	e.defaultHandlerFunc = f
}

func (e *ErrorPages) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	er, ok := r.Context().Value(CtxErrorRecord).(*ErrorRecord)
	if ok {
		code := er.StatusCode
		if f, ok := e.Map[code]; ok {
			f(w, r, er)
			return
		}
		// default rendering
		e.defaultHandlerFunc(w, r, er)
	}
	e.defaultHandlerFunc(w, r, &ErrorRecord{
		StatusCode: http.StatusNotFound,
		Message:    "Not found",
	})
}
