package authproxy

import (
	"reflect"
	"time"

	"github.com/pkg/errors"
)

type HandlersOption func(v interface{}) error

func ErrorPagesOption(er *ErrorPages) HandlersOption {
	return func(v interface{}) error {
		switch x := v.(type) {
		case openidAuthenticateHandlers:
			x.errorPages = er
		default:
			return errors.Errorf("Unsupported type %s", reflect.TypeOf(v))
		}
		return nil
	}
}

func SessionNameOption(sessionName string) HandlersOption {
	return func(v interface{}) error {
		switch x := v.(type) {
		case openidAuthenticateHandlers:
			x.sessionName = sessionName
		default:
			return errors.Errorf("Unsupported type %s", reflect.TypeOf(v))
		}
		return nil
	}
}

func NonceTimeoutOption(timeout time.Duration) HandlersOption {
	return func(v interface{}) error {
		switch x := v.(type) {
		case openidAuthenticateHandlers:
			x.nonceStore = NewNonceStore(timeout)
		default:
			return errors.Errorf("Unsupported type %s", reflect.TypeOf(v))
		}
		return nil
	}
}
