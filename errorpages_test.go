package authproxy

import (
	"html/template"
	"log"
	"net/http"
	"testing"
)

func TestErrorPages(t *testing.T) {
	t.SkipNow()
	er := &ErrorRecord{
		Code:    404,
		Message: "Not Found",
	}
	tpl, err := template.ParseFiles("./assets/html/error.html.tpl")
	if err != nil {
		panic(err)
	}

	http.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		tpl.Execute(w, er)
	}))

	log.Fatal(http.ListenAndServe("localhost:8989", nil))
}
