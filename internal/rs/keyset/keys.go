package keyset

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"sync"
	"time"
)

var ErrUnkonwnKey = errors.New("unknown key")

type KeySet struct {
	jwksURL  string
	client   *http.Client
	interval time.Duration
	now      func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time

	jwk  jwk
	jwks jwks
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func NewKeySet(client *http.Client, jwksURL string) *KeySet {
	return &KeySet{
		jwksURL:  jwksURL,
		client:   client,
		interval: 30 * time.Second,
		now:      time.Now,
		keys:     map[string]*rsa.PublicKey{},
	}
}

func parseJWK(j *jwk) (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, ErrUnkonwnKey
	}

	dn, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, ErrUnkonwnKey
	}
	de, err := base64.RawStdEncoding.DecodeString(j.E)
	if err != nil {
		return nil, ErrUnkonwnKey
	}

	n := new(big.Int).SetBytes(dn)
	e := int(new(big.Int).SetBytes(de).Int64())

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}
