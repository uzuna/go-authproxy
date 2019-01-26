package authproxy

import "net/http"

func Validate() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {

		fn := func(w http.ResponseWriter, r *http.Request) {
			// check expire
		}
		return http.HandlerFunc(fn)
	}
}
