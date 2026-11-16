package registry

import (
	"crypto/subtle"
	"slices"
)

type Client struct {
	Secret                 string
	RedirectURIs           []string
	PostLogoutRedirectURIs []string
}

type Clients struct {
	clients map[string]Client
}

func NewClients() *Clients {
	return &Clients{
		clients: map[string]Client{
			"tegata-sample": {
				Secret: "dummy-secret",
				RedirectURIs: []string{
					"http://localhost:9999/callback",
				},
			},
			"tegata-rp": {
				Secret: "rp-secret",
				RedirectURIs: []string{
					"http://127.0.0.1:5556/callback",
				},
				PostLogoutRedirectURIs: []string{
					"http://127.0.0.1:5556/",
				},
			},
			"conformance": {
				Secret: "conformance-secret",
				RedirectURIs: []string{
					"https://localhost.emobix.co.uk:8443/test/a/tegata/callback",
				},
				PostLogoutRedirectURIs: []string{
					"https://localhost.emobix.co.uk:8443/test/a/tegata/post_logout_redirect",
				},
			},
			"conformance2": {
				Secret: "conformance2-secret",
				RedirectURIs: []string{
					"https://localhost.emobix.co.uk:8443/test/a/tegata/callback",
				},
			},
		},
	}
}

func (s *Clients) ValidateRedirectURI(clientID string, uri string) bool {
	c, ok := s.clients[clientID]
	if !ok {
		return false
	}
	return slices.Contains(c.RedirectURIs, uri)
}

func (s *Clients) Authenticate(clientID string, secret string) bool {
	c, ok := s.clients[clientID]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(c.Secret), []byte(secret)) == 1
}

func (s *Clients) ValidatePostLogoutRedirectURI(clientID string, uri string) bool {
	c, ok := s.clients[clientID]
	if !ok {
		return false
	}
	return slices.Contains(c.PostLogoutRedirectURIs, uri)
}
