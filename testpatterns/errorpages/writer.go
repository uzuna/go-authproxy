package errorpages

import "net/http"

// ErrorWriter is similar http.Error().
// Thisis write error page bytes to ResponceWriter
type ErrorWriter interface {
	Error(w http.ResponseWriter, r *http.Request, err string, code int)
}
