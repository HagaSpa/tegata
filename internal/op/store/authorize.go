package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrAuthorizeRequestNotFound = errors.New("authorize request not found")

type AuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	ResponseType        string
	Scope               string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type AuthorizeRequests struct {
	mu       sync.Mutex
	requests map[string]*AuthorizeRequest
	now      func() time.Time
}

func NewAuthorizeRequests() *AuthorizeRequests {
	return &AuthorizeRequests{
		requests: make(map[string]*AuthorizeRequest),
		now:      time.Now,
	}
}

func (s *AuthorizeRequests) Save(req *AuthorizeRequest) (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("generate rand: %w", err)
	}
	key := base64.RawURLEncoding.EncodeToString(b)
	expiredAt := s.now().Add(10 * time.Minute)
	cp := *req
	cp.ExpiresAt = expiredAt
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[key] = &cp
	return key, nil
}

func (s *AuthorizeRequests) Find(key string) (*AuthorizeRequest, error) {
	req, err := s.lookup(key, false)
	if err != nil {
		return nil, err
	}
	return req, err
}

func (s *AuthorizeRequests) FindAndDelete(key string) (*AuthorizeRequest, error) {
	req, err := s.lookup(key, true)
	if err != nil {
		return nil, err
	}
	return req, err
}

func (s *AuthorizeRequests) lookup(key string, remove bool) (*AuthorizeRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	req := s.requests[key]
	if req == nil {
		return nil, ErrAuthorizeRequestNotFound
	}
	if remove {
		delete(s.requests, key)
	}
	if req.ExpiresAt.Before(s.now()) {
		return nil, ErrAuthorizeRequestNotFound
	}
	cp := *req
	return &cp, nil
}
