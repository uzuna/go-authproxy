package nonce

import (
	"fmt"
	"sync"
	"time"
)

func NewNonceStore(lifeTime time.Duration) *NonceStore {
	return &NonceStore{
		lock:     new(sync.Mutex),
		data:     make(map[string]struct{}),
		lifeTime: lifeTime,
	}
}

type NonceStore struct {
	lock     *sync.Mutex
	data     map[string]struct{}
	lifeTime time.Duration
}

func (s *NonceStore) Get() string {
	nonce := fmt.Sprintf("%x%x",
		time.Now().Unix(),
		time.Now().UnixNano(),
	)
	s.data[nonce] = struct{}{}

	// remove nonce when over lifetime
	go func() {
		time.Sleep(s.lifeTime)
		s.CheckOnce(nonce)
	}()
	return nonce
}

func (s *NonceStore) CheckOnce(nonce string) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	if _, ok := s.data[nonce]; ok {
		delete(s.data, nonce)
		return ok
	}
	return false
}
