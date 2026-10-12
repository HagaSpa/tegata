package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrInvalidCode = errors.New("invalid code")

type Code struct {
	ClientID      string
	RedirectURI   string
	Scope         string
	CodeChallenge string
	Nonce         string
	Sub           string
	ExpiresAt     time.Time
}

type Codes struct {
	mu    sync.Mutex
	codes map[string]*Code
	now   func() time.Time
}

func NewCodes() *Codes {
	return &Codes{
		codes: make(map[string]*Code),
		now:   time.Now,
	}
}

func (s *Codes) Issue(
	clientID string,
	redirectURI string,
	scope string,
	codeChallenge string,
	nonce string,
	sub string,
) (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("generate rand: %w", err)
	}
	key := base64.RawURLEncoding.EncodeToString(b)
	expiresAt := s.now().Add(5 * time.Minute)
	code := &Code{
		ClientID:      clientID,
		RedirectURI:   redirectURI,
		Scope:         scope,
		CodeChallenge: codeChallenge,
		Nonce:         nonce,
		Sub:           sub,
		ExpiresAt:     expiresAt,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.codes[key] = code
	return key, nil
}

func (s *Codes) Consume(key string) (*Code, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	code := s.codes[key]
	if code == nil {
		return nil, ErrInvalidCode
	}
	delete(s.codes, key)
	if code.ExpiresAt.Before(s.now()) {
		return nil, ErrInvalidCode
	}
	return code, nil
}
