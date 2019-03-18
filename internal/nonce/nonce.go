package nonce

import (
	"fmt"
	"sync"
	"time"
)

// NewStore godoc
// Create Nonce Store with timeout
func NewStore(lifeTime time.Duration) Store {
	return &store{
		lock:     new(sync.Mutex),
		data:     make(map[string]struct{}),
		lifeTime: lifeTime,
	}
}

// Store godoc
// Nonce is onetime id so it can check only once after get.
type Store interface {
	Get() string
	CheckOnce(nonce string) bool
}

// mnonce store implementation storeon memory with timeout
type store struct {
	lock     *sync.Mutex
	data     map[string]struct{}
	lifeTime time.Duration
}

func (s *store) Get() string {
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

func (s *store) CheckOnce(nonce string) bool {
	s.lock.Lock()
	defer s.lock.Unlock()
	if _, ok := s.data[nonce]; ok {
		delete(s.data, nonce)
		return ok
	}
	return false
}
