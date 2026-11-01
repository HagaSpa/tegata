package keyset

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

var (
	ErrUnknownKey       = errors.New("unknown key")
	ErrIssuerMismatched = errors.New("issuer mismatch")
)

const discoveryPath = "/.well-known/openid-configuration"

type KeySet struct {
	jwksURL  string
	client   *http.Client
	interval time.Duration
	now      func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
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

type openIDConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
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

func (ks *KeySet) Key(kid string) (*rsa.PublicKey, error) {
	ks.mu.Lock()
	defer ks.mu.Unlock()

	k := ks.keys[kid]
	if k != nil {
		return k, nil
	}

	if ks.now().Sub(ks.fetchedAt) < ks.interval {
		return nil, ErrUnknownKey
	}

	ks.fetchedAt = ks.now()
	mp, err := fetch(ks.client, ks.jwksURL)
	if err != nil {
		return nil, err
	}

	ks.keys = mp
	k = ks.keys[kid]
	if k != nil {
		return k, nil
	}

	return nil, ErrUnknownKey
}

func parseJWK(j *jwk) (*rsa.PublicKey, error) {
	if j.Kty != "RSA" {
		return nil, ErrUnknownKey
	}

	dn, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, ErrUnknownKey
	}
	de, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, ErrUnknownKey
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

	var j jwks
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return nil, fmt.Errorf("invalid json web keys: %w", err)
	}

	pubKeys := map[string]*rsa.PublicKey{}
	for _, v := range j.Keys {
		pubKey, err := parseJWK(&v)
		if err != nil {
			continue
		}
		pubKeys[v.Kid] = pubKey
	}

	return pubKeys, nil
}

func GetJWKSURI(client *http.Client, issuer string) (string, error) {
	url := strings.TrimSuffix(issuer, "/") + discoveryPath
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("failed to access url: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed response code: %d", resp.StatusCode)
	}

	var o openIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&o); err != nil {
		return "", fmt.Errorf("invalid openIDConfiguration schema: %w", err)
	}

	if o.Issuer != issuer {
		return "", fmt.Errorf("%w: provided %q, discovered %q", ErrIssuerMismatched, issuer, o.Issuer)
	}

	return o.JWKSURI, nil
}
