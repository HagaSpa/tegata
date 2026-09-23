package auth

type Client struct {
	Secret      string
	RedirectURI string
}

type ClientStore struct {
	clients map[string]Client
}

func NewClientStore() *ClientStore {
	return &ClientStore{
		clients: map[string]Client{
			"tegata-sample": {
				Secret:      "dummy-secret",
				RedirectURI: "http://localhost:9999/callback",
			},
		},
	}
}
