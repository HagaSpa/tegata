package store

import (
	"errors"
	"maps"
	"sync"
	"time"
)

var ErrInvalidRefreshToken = errors.New("invalid refresh token")

type RefreshToken struct {
	ClientID  string
	Sub       string
	Scope     string
	FamilyID  string
	used      bool
	ExpiresAt time.Time
}

type RefreshTokens struct {
	mu     sync.Mutex
	tokens map[string]*RefreshToken
	now    func() time.Time
}

func NewRefreshTokens() *RefreshTokens {
	return &RefreshTokens{
		tokens: make(map[string]*RefreshToken),
		now:    time.Now,
	}
}

func (s *RefreshTokens) Issue(
	clientID string,
	sub string,
	scope string,
) string {
	key := generateRandomString()
	familyID := generateRandomString()
	expiresAt := s.now().AddDate(0, 0, 30)
	rt := &RefreshToken{
		ClientID:  clientID,
		Sub:       sub,
		Scope:     scope,
		FamilyID:  familyID,
		ExpiresAt: expiresAt,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[key] = rt
	return key
}

func (s *RefreshTokens) Rotate(
	key string,
	clientID string,
) (string, *RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur := s.tokens[key]
	if cur == nil {
		return "", nil, ErrInvalidRefreshToken
	}
	if cur.ClientID != clientID {
		return "", nil, ErrInvalidRefreshToken
	}
	if cur.ExpiresAt.Before(s.now()) {
		return "", nil, ErrInvalidRefreshToken
	}
	if cur.used {
		maps.DeleteFunc(s.tokens, func(_ string, v *RefreshToken) bool {
			return v.FamilyID == cur.FamilyID
		})
		return "", nil, ErrInvalidRefreshToken
	}

	cur.used = true
	nextKey := generateRandomString()
	next := &RefreshToken{
		ClientID:  cur.ClientID,
		Sub:       cur.Sub,
		Scope:     cur.Scope,
		FamilyID:  cur.FamilyID,
		ExpiresAt: cur.ExpiresAt,
	}
	s.tokens[nextKey] = next
	return nextKey, next, nil
}
