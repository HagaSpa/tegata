package store

import (
	"sync"
	"time"
)

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
	refreshToken := generateRandomString()
	familyID := generateRandomString()
	expiresAt := s.now().AddDate(0, 0, 30)
	token := &RefreshToken{
		ClientID:  clientID,
		Sub:       sub,
		Scope:     scope,
		FamilyID:  familyID,
		ExpiresAt: expiresAt,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tokens[refreshToken] = token
	return refreshToken
}
