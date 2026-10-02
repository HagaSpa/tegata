package handler

import "github.com/HagaSpa/tegata/auth"

type ClientAuthenticator interface {
	Authenticate(clientID, secret string) bool
}

type CodeConsumer interface {
	Consume(code string) (*auth.Code, error)
}

type Signer interface {
	Sign(*auth.Claim) (*auth.JWT, error)
}

type TokenHandler struct {
	client ClientAuthenticator
	codes  CodeConsumer
	signer Signer
	issuer string
}

func NewTokenHandler(
	client ClientAuthenticator,
	codes CodeConsumer,
	signer Signer,
	issuer string,
) *TokenHandler {
	return &TokenHandler{
		client: client,
		codes:  codes,
		signer: signer,
		issuer: issuer,
	}
}
