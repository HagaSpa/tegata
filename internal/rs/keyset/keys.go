package keyset

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

func fetch(client *http.Client, url string) (map[string]*rsa.PublicKey, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to access url: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed response code: %d", resp.StatusCode)
	}

	var jwks jwks
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("invalid json web keys: %w", err)
	}

	pubKeys := map[string]*rsa.PublicKey{}
	for _, v := range jwks.Keys {
		pubKey, err := parseJWK(&v)
		if err != nil {
			continue
		}
		pubKeys[v.Kid] = pubKey
	}

	return pubKeys, nil
}
