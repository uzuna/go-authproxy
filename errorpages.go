package authproxy

import "net/http"

type ErrorHandleFunc func(w http.ResponseWriter, r *http.Request, e *ErrorRecord)

type ErrorRecord struct {
	Code    int
	Message string
}

func NewErrorPages() *ErrorPages {
	return &ErrorPages{
		Map: make(map[int]ErrorHandleFunc),
	}
}

// ErrorPages is serve Custom Error page
type ErrorPages struct {
	Map map[int]ErrorHandleFunc
}

func (e *ErrorPages) Static(code int, doc string) {
	e.Map[code] = func(w http.ResponseWriter, r *http.Request, e *ErrorRecord) {
		w.WriteHeader(code)
		w.Write([]byte(doc))
	}
}

func (e *ErrorPages) ErrorHandleFunc(code int, f ErrorHandleFunc) {
	e.Map[code] = f
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
