package store

import (
	"errors"
	"sync"
	"time"
)

var ErrInvalidSession = errors.New("invalid session")

type Session struct {
	Sub      string
	AuthTime time.Time
}

type Sessions struct {
	mu sync.Mutex
	ss map[string]*Session
}

func NewSessions() *Sessions {
	return &Sessions{
		ss: make(map[string]*Session),
	}
}

func (s *Sessions) Save(
	sub string,
	authTime time.Time,
) string {
	key := generateRandomString()
	session := &Session{
		Sub:      sub,
		AuthTime: authTime,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ss[key] = session
	return key
}

func (s *Sessions) Get(
	key string,
) (*Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session := s.ss[key]
	if session == nil {
		return nil, ErrInvalidSession
	}
	return session, nil
}
