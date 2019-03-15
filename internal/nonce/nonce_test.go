package nonce_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/uzuna/go-authproxy/internal/nonce"
)

func TestNonce(t *testing.T) {
	s := nonce.NewStore(time.Second)

	nonce := s.Get()
	assert.True(t, s.CheckOnce(nonce))
	assert.False(t, s.CheckOnce(nonce))

	nonce = s.Get()
	time.Sleep(time.Millisecond * 1100)
	assert.False(t, s.CheckOnce(nonce))
}
