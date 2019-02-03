package authproxy

import "net/http"

// ErrorHandleFunc is implementation of ErrorPage Renderer
type ErrorHandleFunc func(w http.ResponseWriter, r *http.Request, e *ErrorRecord)

// ErrorRecord is body of Error record on Autenticate Process
type ErrorRecord struct {
	Code    int
	Message string
}

// NewErrorPages create instance of ErrorPages
func NewErrorPages() *ErrorPages {
	return &ErrorPages{
		Map: make(map[int]ErrorHandleFunc),
	}
}

// ErrorPages is serve Custom Error page
type ErrorPages struct {
	Map map[int]ErrorHandleFunc
}

// Static register static page to match http status code.
func (e *ErrorPages) Static(code int, doc string) {
	e.Map[code] = func(w http.ResponseWriter, r *http.Request, e *ErrorRecord) {
		w.WriteHeader(code)
		w.Write([]byte(doc))
	}
}

func (e *ErrorPages) ErrorHandleFunc(code int, f ErrorHandleFunc) {
	e.Map[code] = f
}

func (e *ErrorPages) Error(w http.ResponseWriter, r *http.Request, err string, code int) {
	e.Map[code](w, r, &ErrorRecord{Code: code, Message: err})
}

func (e *ErrorPages) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	code, ok := r.Context().Value(CtxHTTPStatus).(int)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not found"))
	}
	er, ok := r.Context().Value(CtxErrorRecord).(*ErrorRecord)
	if ok {
		if f, ok := e.Map[code]; ok {
			f(w, r, er)
			return
		}
		w.WriteHeader(code)
		w.Write([]byte(er.Message))
		return
	}
	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("Not found"))
}
