package errorpages

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorPages(t *testing.T) {
	erp, err := NewErrorPages()
	checkError(t, err)

	table := []*ErrorRecord{
		&ErrorRecord{
			StatusCode: 400,
			Message:    "Very Bad Request",
		},
		&ErrorRecord{
			StatusCode: 404,
			Message:    "Custom Error Page",
		},
	}

	for _, er := range table {

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)

		mux := http.NewServeMux()
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			erp.Error(w, r, er.Message, er.StatusCode)
		})

		mux.ServeHTTP(rec, req)

		b := new(bytes.Buffer)
		_, err = io.Copy(b, rec.Body)
		checkError(t, err)
		assert.Equal(t, er.StatusCode, rec.Code)
		assert.Contains(t, b.String(), fmt.Sprintf("<title>%d:%s</title>", er.StatusCode, er.Message))
	}
}
func TestErrorMiddleware(t *testing.T) {
	erp, err := NewErrorPages()
	checkError(t, err)

	table := []*ErrorRecord{
		&ErrorRecord{
			StatusCode: 404,
			Message:    "Not found",
		},
	}
	for _, er := range table {

		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)

		handleWrapper := ErrorWriteMiddleware(erp)
		handle := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		})
		mux := http.NewServeMux()
		mux.Handle("/", handleWrapper(handle))

		mux.ServeHTTP(rec, req)

		b := new(bytes.Buffer)
		_, err = io.Copy(b, rec.Body)
		checkError(t, err)
		assert.Equal(t, er.StatusCode, rec.Code)
		assert.Contains(t, b.String(), fmt.Sprintf("<title>%d:%s</title>", er.StatusCode, er.Message))
	}
}

func checkError(t *testing.T, err error) {
	if err != nil {
		t.Logf("%+v", err)
		t.FailNow()
	}
}
