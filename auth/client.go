package auth

import (
	"crypto/subtle"
	"slices"
)

type Client struct {
	Secret       string
	RedirectURIs []string
}

type ClientStore struct {
	clients map[string]Client
}

func NewClientStore() *ClientStore {
	return &ClientStore{
		clients: map[string]Client{
			"tegata-sample": {
				Secret: "dummy-secret",
				RedirectURIs: []string{
					"http://localhost:9999/callback",
				},
			},
		},
	}
}

func (s *ClientStore) ValidateRedirectURI(clientID string, uri string) bool {
	c, ok := s.clients[clientID]
	if !ok {
		return false
	}
	return slices.Contains(c.RedirectURIs, uri)
}

func (s *ClientStore) Authenticate(clientID string, secret string) bool {
	c, ok := s.clients[clientID]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) == 1
}
