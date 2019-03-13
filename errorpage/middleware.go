package errorpage

import (
	"net/http"
)

// ErrorWriteMiddleware
// Muxのクローズ時に介入してWriteがなければErrorを代わりに入れる
func ErrorWriteMiddleware(ew ErrorWriter) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			wi := &responseWriteInterrupter{
				statusCode: 404,
				writer:     w,
			}
			defer func() {
				if !wi.written {
					ew.Error(w, r, "Not found", wi.statusCode)
				}
			}()
			next.ServeHTTP(wi, r)
		}
		return http.HandlerFunc(fn)
	}
}

type responseWriteInterrupter struct {
	written    bool
	statusCode int
	writer     http.ResponseWriter
}

func (w *responseWriteInterrupter) Header() http.Header {
	return w.writer.Header()
}

func (w *responseWriteInterrupter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.writer.WriteHeader(statusCode)
}

func (w *responseWriteInterrupter) Write(b []byte) (int, error) {
	w.written = true
	return w.writer.Write(b)
}
